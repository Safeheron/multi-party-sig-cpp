#include "P1Context.h"
#include "message.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/util.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-commitment/com256.h"

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
namespace sign {

bool P1Context::CreateContext(const safeheron::curve::CurveType &c_type, const std::string &p1_key_share_base64, const safeheron::bignum::BN &m) {
    P1KeyShare p1_key_share;
    if (!p1_key_share.FromBase64(p1_key_share_base64)) return false;

    if (!check_ecdsa_curve(c_type)) return false;
    c_type_ = c_type;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    if (!(p1_key_share.x1_ >= 0 && p1_key_share.x1_ < q)
        || p1_key_share.pail_pub_.n().BitLength() <= 2046)
        return false;
    key_share_ = p1_key_share;

    m_ = m;

    return true;
}

bool P1Context::Step0(std::string &out_msg) {
    sid1_ = safeheron::rand::RandomBytes(32);
    sid1_blind_factor_= safeheron::rand::RandomBytes(32);

    safeheron::commitment::HashCommit256 sha256_com;
    sha256_com.UpdateString(sid1_);

    P1Message0 p1_msg0;
    p1_msg0.sid1_commitment_ = sha256_com.Commit(sid1_blind_factor_);
    if (!p1_msg0.ToBase64(out_msg)) return false;

    return true;
}

bool P1Context::Step1(const std::string &in_msg, std::string &out_msg) {
    P2Message0 p2_msg0;
    if (!p2_msg0.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    if (sid1_.length() != p2_msg0.sid2_.length()) return false;

    sid_ = sid1_;
    for (size_t k = 0; k < sid1_.length(); ++k) {
        sid_[k] ^= p2_msg0.sid2_[k];
    }

    k1_ = safeheron::rand::RandomBNLt(q);
    safeheron::curve::CurvePoint R1 = curv->g * k1_;
    d_log_proof_R1_.SetSalt(sid_ + "1");
    d_log_proof_R1_.ProveEx(k1_, c_type_);

    t_ = safeheron::rand::RandomBNLt(q);

    // (com-prove, sid || 1, R1, d_log_proof_R1_.A_, t_)
    safeheron::commitment::HashCommit256 sha256_com;
    sha256_com.UpdateString(sid_ + "1");
    sha256_com.UpdateCurvePoint(R1);
    sha256_com.UpdateCurvePoint(d_log_proof_R1_.A_);
    sha256_com.UpdateBN(t_);
    zk_pk_blind_factor_ = safeheron::rand::RandomBytes(32);

    P1Message1 p1_msg1;
    p1_msg1.sid1_ = sid1_;
    p1_msg1.sid1_blind_factor_ = sid1_blind_factor_;
    p1_msg1.zk_pk_commitment_= sha256_com.Commit(zk_pk_blind_factor_);
    if (!p1_msg1.ToBase64(out_msg)) return false;

    return true;
}

bool P1Context::Step2(const std::string &in_msg, std::string &out_msg) {
    P2Message1 p2_msg1;
    if (!p2_msg1.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    p2_msg1.d_log_proof_R2_.SetSalt(sid_ + "2");
    if (!p2_msg1.d_log_proof_R2_.Verify(p2_msg1.R2_)) return false;

    R_ = (p2_msg1.R2_ * t_) * k1_;
    r_ = R_.x() % q;

    P1Message2 p1_msg2;
    p1_msg2.R1_ = curv->g * k1_;
    p1_msg2.d_log_proof_R1_ = d_log_proof_R1_;
    p1_msg2.t_ = t_;
    p1_msg2.zk_pk_blind_factor_ = zk_pk_blind_factor_;
    if (!p1_msg2.ToBase64(out_msg)) return false;

    return true;
}

bool P1Context::Step3(const std::string &in_msg) {
    P2Message2 p2_msg2;
    if (!p2_msg2.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    safeheron::bignum::BN k1_inv = k1_.InvM(q);
    safeheron::bignum::BN s_prime = key_share_.pail_priv_.Decrypt(p2_msg2.c3_);

    const safeheron::bignum::BN q2 = q * q;
    const safeheron::bignum::BN q3 = q * q * q;

    // s = (k2_inv * r * x2 + k2_inv * m) mod q + ((k2_inv * r) mod q) * (x1 + q) + rho*q
    if (s_ > q3 + q2 * 2 - q * 3 ) return false;
    s_ = (k1_inv * s_prime) % q;

    v_ = (R_.y().IsOdd() ? 1 : 0) | ((R_.x() != r_) ? 2 : 0);
    if (s_ > q / 2) {
        s_ = q - s_;
        v_ ^= 1;
    }

    bool ok = safeheron::curve::ecdsa::VerifyPublicKey(key_share_.Q_,
                                                       key_share_.Q_.GetCurveType(),
                                                       m_, r_, s_, v_);
    if (!ok) return false;

    return true;
}

bool P1Context::export_sig(uint8_t *sig64, uint32_t &v) const {
    r_.ToBytes32BE(sig64);
    s_.ToBytes32BE(sig64 + 32);
    v = v_;
    return true;
}

}
}
}
}

