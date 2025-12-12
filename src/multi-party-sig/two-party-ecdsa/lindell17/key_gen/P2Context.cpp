#include "P2Context.h"
#include "message.h"
#include "multi-party-sig/two-party-ecdsa/lindell17/util.h"
#include "crypto-suites/crypto-commitment/com256.h"
#include "crypto-suites/crypto-bn/rand.h"

namespace safeheron{
namespace two_party_ecdsa {
namespace lindell17 {
namespace key_gen {

bool P2Context::CreateContext(const safeheron::curve::CurveType &c_type) {
    if (!check_ecdsa_curve(c_type)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    safeheron::bignum::BN x2 = safeheron::rand::RandomBNLt(q);

    return CreateContext(c_type, x2);
}

bool P2Context::CreateContext(const safeheron::curve::CurveType &c_type, const safeheron::bignum::BN &x2) {
    if (!check_ecdsa_curve(c_type)) return false;
    c_type_ = c_type;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
    if (curv == nullptr) return false;

    const safeheron::bignum::BN &q = curv->n;

    if (!(x2 >= 0 && x2 < q)) return false;

    key_share_.x2_ = x2;

    return true;
}

bool P2Context::Step1(const std::string &in_msg, std::string &out_msg) {
    P1Message1 p1_msg1;
    if (!p1_msg1.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    commitment_ = p1_msg1.commitment_;

    safeheron::curve::CurvePoint Q2 = curv->g * key_share_.x2_;
    safeheron::zkp::dlog::DLogProof_V2 d_log_proof;
    d_log_proof.ProveEx(key_share_.x2_, c_type_);

    P2Message1 p2_msg1;
    p2_msg1.Q2_ = Q2;
    p2_msg1.d_log_proof_Q2_ = d_log_proof;
    if (!p2_msg1.ToBase64(out_msg)) return false;

    return true;
}

bool P2Context::Step2(const std::string &in_msg, std::string &out_msg) {
    P1Message2 p1_msg2;
    if (!p1_msg2.FromBase64(in_msg)) return false;

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type_);
    if (curv == nullptr) return false;

    // decommits( Q1 ,d_log_proof_.A_; blind_factor )
    safeheron::commitment::HashCommit256 sha256_com;
    sha256_com.UpdateCurvePoint(p1_msg2.Q1_);
    sha256_com.UpdateCurvePoint(p1_msg2.d_log_proof_Q1_.A_);
    if (!sha256_com.OpenAndVerify(p1_msg2.blind_factor_, commitment_)) return false;

    // verify DLOG proof of Q1
    if (!p1_msg2.d_log_proof_Q1_.Verify(p1_msg2.Q1_)) return false;

    //verify pail N proof
    if (!p1_msg2.pail_n_proof_.Verify(p1_msg2.pail_pub_)) return false;

    key_share_.Q_ = curv->g * key_share_.x2_ + p1_msg2.Q1_;

    if (!(p1_msg2.c_ > 0 && p1_msg2.c_ < p1_msg2.pail_pub_.n_sqr() && p1_msg2.c_.Gcd(p1_msg2.pail_pub_.n_sqr()) == 1)) return false;

    key_share_.pail_pub_ = p1_msg2.pail_pub_;
    key_share_.c_ = p1_msg2.c_;

    safeheron::zkp::pdl::PDLStatement statement(p1_msg2.c_, p1_msg2.Q1_, p1_msg2.pail_pub_);
    if (!pdl_verifier_.Init(statement)) return false;

    safeheron::zkp::pdl::PDLVMessage1 pdl_v_message1;
    if (!pdl_verifier_.Step1(pdl_v_message1)) return false;

    P2Message2 p2_msg2;
    p2_msg2.pdl_v_message1_ = pdl_v_message1;
    if (!p2_msg2.ToBase64(out_msg)) return false;

    return true;
}

bool P2Context::Step3(const std::string &in_msg, std::string &out_msg) {
    P1Message3 p1_msg3;
    if (!p1_msg3.FromBase64(in_msg)) return false;

    safeheron::zkp::pdl::PDLVMessage2 pdl_v_message2;
    if (!pdl_verifier_.Step2(p1_msg3.pdl_p_message1_, pdl_v_message2)) return false;

    P2Message3 p2_msg3;
    p2_msg3.pdl_v_message2_ = pdl_v_message2;

    if (!p2_msg3.ToBase64(out_msg)) return false;

    return true;
}

bool P2Context::Step4(const std::string &in_msg) {
    P1Message4 p1_msg4;
    if (!p1_msg4.FromBase64(in_msg)) return false;

    //verify pdl
    if (!pdl_verifier_.Accept(p1_msg4.pdl_p_message2_)) return false;

    return true;
}

bool P2Context::export_key_share(std::string &p2_key_share_base64) const {
    if (!key_share_.ToBase64(p2_key_share_base64)) return false;

    return true;
}
}
}
}
}



