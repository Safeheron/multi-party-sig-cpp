#include "P2Context.h"
#include "message.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/util.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-commitment/com256.h"

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
namespace sign {
bool P2Context::CreateContext(const safeheron::curve::CurveType &c_type, const std::string &p2_key_share_base64, const safeheron::bignum::BN &m) {
    P2KeyShare p2_key_share;
    if (!p2_key_share.FromBase64(p2_key_share_base64)) return false;

    if (!check_ecdsa_curve(c_type)) return false;
    c_type_ = c_type;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    if (!(p2_key_share.x2_ >= 0 && p2_key_share.x2_ < q)
        || !(p2_key_share.c_ > 0 && p2_key_share.c_ < p2_key_share.pail_pub_.n_sqr())) return false;
    key_share_ = p2_key_share;

    m_ = m;

    return true;
}

bool P2Context::Step0(const std::string &in_msg, std::string &out_msg) {
    P1Message0 p1_msg0;
    if (!p1_msg0.FromBase64(in_msg)) return false;

    sid1_commitment_ = p1_msg0.sid1_commitment_;

    sid2_ = safeheron::rand::RandomBytes(32);

    P2Message0 p2_msg0;
    p2_msg0.sid2_ = sid2_;
    if (!p2_msg0.ToBase64(out_msg)) return false;

    return true;
}

bool P2Context::Step1(const std::string &in_msg, std::string &out_msg) {
    P1Message1 p1_msg1;
    if (!p1_msg1.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    safeheron::commitment::HashCommit256 sha256_com;
    sha256_com.UpdateString(p1_msg1.sid1_);
    if (!sha256_com.OpenAndVerify(p1_msg1.sid1_blind_factor_, sid1_commitment_)) return false;

    if (sid2_.length() != p1_msg1.sid1_.length()) return false;

    sid_ = sid2_;
    for (size_t k = 0; k < sid2_.length(); ++k) {
        sid_[k] ^= p1_msg1.sid1_[k];
    }

    zk_pk_commmitment_ = p1_msg1.zk_pk_commitment_;

    k2_ = safeheron::rand::RandomBNLt(q);
    safeheron::curve::CurvePoint R2 = curv->g * k2_;
    safeheron::zkp::dlog::DLogProof_V2 d_log_proof_R2;
    d_log_proof_R2.SetSalt(sid_ + "2");
    d_log_proof_R2.ProveEx(k2_, c_type_);

    P2Message1 p2_msg1;
    p2_msg1.R2_ = R2;
    p2_msg1.d_log_proof_R2_ = d_log_proof_R2;
    if (!p2_msg1.ToBase64(out_msg)) return false;

    return true;
}

bool P2Context::Step2(const std::string &in_msg, std::string &out_msg) {
    P1Message2 p1_msg2;
    if (!p1_msg2.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    if ((p1_msg2.t_ % q) == 0) return false;

    // (decom-proof, sid || 1, R1, d_log_proof_R1_.A_, t_)
    safeheron::commitment::HashCommit256 sha256_com;
    sha256_com.UpdateString(sid_ + "1");
    sha256_com.UpdateCurvePoint(p1_msg2.R1_);
    sha256_com.UpdateCurvePoint(p1_msg2.d_log_proof_R1_.A_);
    sha256_com.UpdateBN(p1_msg2.t_);
    if (!sha256_com.OpenAndVerify(p1_msg2.zk_pk_blind_factor_, zk_pk_commmitment_)) return false;

    // verify DLOG proof of R1
    p1_msg2.d_log_proof_R1_.SetSalt(sid_ + "1");
    if (!p1_msg2.d_log_proof_R1_.Verify(p1_msg2.R1_)) return false;

    k2_prime_ = (k2_ * p1_msg2.t_) % q;
    R_ = p1_msg2.R1_ * k2_prime_;
    safeheron::bignum::BN r = R_.x() % q;
    // Sample rho in (0, q^2)
    safeheron::bignum::BN rho = safeheron::rand::RandomBNLt(q * q);
    safeheron::bignum::BN k2_inv = k2_prime_.InvM(q);
    // c1 = Enc(pail_pub, rho*q + (k2_inv * r * x2 + k2_inv * m) mod q)
    safeheron::bignum::BN c1 = key_share_.pail_pub_.Encrypt(rho * q + (k2_inv * r * key_share_.x2_ + k2_inv * m_) % q);
    // v = (k2_inv * r) mod q
    safeheron::bignum::BN v = (k2_inv * r) % q;
    // c2 = Enc(pail_pub, v * (x1 + q) ;r)
    safeheron::bignum::BN c2 = key_share_.pail_pub_.HomomorphicMulPlain(key_share_.pail_pub_.HomomorphicAdd(key_share_.c_, key_share_.pail_pub_.EncryptWithR(q, safeheron::bignum::BN(1))), v);
    // c3 = HAdd(c1, c2) = Enc(pail_pub, [rho*q + (k2_inv * r * x2 + k2_inv * m) mod q] + [(k2_inv * r) mod q] * (x1 + q))
    safeheron::bignum::BN c3 = key_share_.pail_pub_.HomomorphicAdd(c1,c2);

    P2Message2 p2_msg_2;
    p2_msg_2.c3_ = c3;
    if (!p2_msg_2.ToBase64(out_msg)) return false;

    return true;
}
}
}
}
}

