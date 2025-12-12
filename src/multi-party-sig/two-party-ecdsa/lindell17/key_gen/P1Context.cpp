#include "P1Context.h"
#include "message.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-commitment/com256.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/util.h"

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
namespace key_gen {

bool P1Context::CreateContext(const safeheron::curve::CurveType &c_type) {
    if (!check_ecdsa_curve(c_type)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    safeheron::bignum::BN x1 = safeheron::rand::RandomBNLt(q);

    return CreateContext(c_type, x1);
}

bool P1Context::CreateContext(const safeheron::curve::CurveType &c_type, const safeheron::bignum::BN &x1) {
    if (!check_ecdsa_curve(c_type)) return false;
    c_type_ = c_type;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    if (!(x1 >= 0 && x1 < q)) return false;

    key_share_.x1_ = x1;

    safeheron::pail::CreateKeyPair2048(key_share_.pail_priv_, key_share_.pail_pub_);

    return true;
}

bool P1Context::Step1(std::string &out_msg) {
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    safeheron::curve::CurvePoint Q1 = curv->g * key_share_.x1_;
    d_log_proof_Q1_.ProveEx(key_share_.x1_, c_type_);

    // commitment = H( Q1 || d_log_proof_.A_ || blind_factor )
    safeheron::commitment::HashCommit256 sha256_com;
    sha256_com.UpdateCurvePoint(Q1);
    sha256_com.UpdateCurvePoint(d_log_proof_Q1_.A_);
    blind_factor_ = safeheron::rand::RandomBytes(32);

    P1Message1 p1_msg1;
    p1_msg1.commitment_ = sha256_com.Commit(blind_factor_);
    if (!p1_msg1.ToBase64(out_msg)) return false;

    return true;
}

bool P1Context::Step2(const std::string &in_msg, std::string &out_msg) {
    P2Message1 p2_msg1;
    if (!p2_msg1.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    if (!p2_msg1.d_log_proof_Q2_.Verify(p2_msg1.Q2_)) return false;

    safeheron::curve::CurvePoint Q1 = curv->g * key_share_.x1_;
    key_share_.Q_ = Q1 + p2_msg1.Q2_;

    r_ = safeheron::rand::RandomBNLtCoPrime(key_share_.pail_pub_.n());
    c_ = key_share_.pail_pub_.EncryptWithR(key_share_.x1_, r_);

    safeheron::zkp::pail::PailNProof pail_n_proof;
    pail_n_proof.Prove(key_share_.pail_priv_);

    P1Message2 p1_msg2;
    p1_msg2.Q1_ = Q1;
    p1_msg2.d_log_proof_Q1_ = d_log_proof_Q1_;
    p1_msg2.blind_factor_ = blind_factor_;
    p1_msg2.c_ = c_;
    p1_msg2.pail_pub_ = key_share_.pail_pub_;
    p1_msg2.pail_n_proof_ = pail_n_proof;

    if (!p1_msg2.ToBase64(out_msg)) return false;

    return true;
}

bool P1Context::Step3(const std::string &in_msg, std::string &out_msg) {
    P2Message2 p2_msg2;
    if (!p2_msg2.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    safeheron::curve::CurvePoint Q1 = curv->g * key_share_.x1_;
    safeheron::zkp::pdl::PDLWitness witness(key_share_.x1_, r_, key_share_.pail_priv_);
    safeheron::zkp::pdl::PDLStatement statement(c_, Q1, key_share_.pail_pub_);
    if (!pdl_prover_.Init(statement, witness)) return false;

    safeheron::zkp::pdl::PDLPMessage1 pdl_p_message1;
    if (!pdl_prover_.Step1(p2_msg2.pdl_v_message1_, pdl_p_message1)) return false;

    P1Message3 p1_msg3;
    p1_msg3.pdl_p_message1_ = pdl_p_message1;
    if (!p1_msg3.ToBase64(out_msg)) return false;

    return true;
}

bool P1Context::Step4(const std::string &in_msg, std::string &out_msg) {
    P2Message3 p2_msg3;
    if (!p2_msg3.FromBase64(in_msg)) return false;

    safeheron::zkp::pdl::PDLPMessage2 pdl_p_message2;
    if (!pdl_prover_.Step2(p2_msg3.pdl_v_message2_,pdl_p_message2)) return false;

    P1Message4 p1_msg4;
    p1_msg4.pdl_p_message2_ = pdl_p_message2;
    if (!p1_msg4.ToBase64(out_msg)) return false;

    return true;
}

bool P1Context::export_key_share(std::string &p1_key_share_b64) const {
    if (!key_share_.ToBase64(p1_key_share_b64)) return false;

    return true;
}

}
}
}
}
