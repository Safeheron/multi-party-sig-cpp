#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/mta.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/round2.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/context.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::gg18::SignKey;
using safeheron::zkp::pail::PailAffRangeSetUp;
using safeheron::zkp::pail::PailAffRangeStatement;
using safeheron::zkp::pail::PailAffRangeWitness;
using safeheron::zkp::pail::PailAffRangeProof;
using safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V1;
using safeheron::zkp::pail::PailAffGroupEleRangeStatement_V1;
using safeheron::zkp::pail::PailAffGroupEleRangeProof_V1;
using safeheron::zkp::pedersen_proof::PedersenStatement;
using safeheron::zkp::pedersen_proof::PedersenWitness;
using safeheron::zkp::pedersen_proof::PedersenProof;
using safeheron::multi_party_ecdsa::gg18::sign::MtA_Step3;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg20{
namespace sign{

void Round2::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        p2p_message_arr_.emplace_back();
    }
}

bool Round2::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round2::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    PailAffRangeSetUp setup_1(sign_key.local_party_.N_tilde_,
                                sign_key.local_party_.h1_,
                                sign_key.local_party_.h2_);
    PailAffRangeStatement statement_1(ctx->local_party_.message_a_,
                                      p2p_message_arr_[pos].message_b_for_k_gamma_,
                                      sign_key.local_party_.pail_pub_,
                                      curv->n);
    bool ok = p2p_message_arr_[pos].bob_proof_1_.Verify(setup_1, statement_1);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify the 'bob_proof1_'!");
        return false;
    }

    PailAffGroupEleRangeSetUp_V1 setup_2(sign_key.local_party_.N_tilde_,
                                         sign_key.local_party_.h1_,
                                         sign_key.local_party_.h2_);
    PailAffGroupEleRangeStatement_V1 statement_2(ctx->local_party_.message_a_,
                                      p2p_message_arr_[pos].message_b_for_k_w_,
                                      sign_key.local_party_.pail_pub_,
                                      sign_key.remote_parties_[pos].g_x_ * ctx->local_party_.l_arr_[pos],
                                      curv->n);
    ok = p2p_message_arr_[pos].bob_proof_2_.Verify(setup_2, statement_2);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify the 'bob_proof2_'!");
        return false;
    }

    return true;
}

bool Round2::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        MtA_Step3(ctx->remote_parties_[i].alpha_for_k_gamma_,
                p2p_message_arr_[i].message_b_for_k_gamma_,
                    sign_key.local_party_.pail_priv_,
                    curv->n);

        MtA_Step3(ctx->remote_parties_[i].alpha_for_k_w_,
                p2p_message_arr_[i].message_b_for_k_w_,
                sign_key.local_party_.pail_priv_,
                curv->n);
    }

    // delta = k * gamma + Sum_{i!=j}{alpha_ij} + Sum_{i!=j}{beta_ij}
    BN delta = (ctx->local_party_.k_ * ctx->local_party_.gamma_) % curv->n;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        delta = (delta + ctx->remote_parties_[i].alpha_for_k_gamma_ + ctx->remote_parties_[i].beta_for_k_gamma_) % curv->n;
    }
    ctx->local_party_.delta_ = delta;

    // sigma = kw + Sum_{i!=j}{u_ij} + Sum_{i!=j}{v_ij}
    BN sigma = (ctx->local_party_.k_ * ctx->local_party_.w_) % curv->n;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        sigma = (sigma + ctx->remote_parties_[i].alpha_for_k_w_ + ctx->remote_parties_[i].beta_for_k_w_) % curv->n;
    }
    ctx->local_party_.sigma_ = sigma;

    BN h = safeheron::rand::RandomBNLt(curv->n);
    BN l = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.H_ = curv->g * h;
    ctx->local_party_.T_ = curv->g * ctx->local_party_.sigma_ + ctx->local_party_.H_ * l;
    ctx->local_party_.l_ = l;
    PedersenStatement pedersen_statement(curv->g, ctx->local_party_.H_, ctx->local_party_.T_);
    PedersenWitness pedersen_witness(ctx->local_party_.sigma_, l);
    ctx->local_party_.pedersen_proof_.Prove(pedersen_statement, pedersen_witness);

    return true;
}

bool Round2::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    Round2BCMessage bc_message;
    bc_message.delta_ = ctx->local_party_.delta_;
    bc_message.H_ = ctx->local_party_.H_;
    bc_message.T_ = ctx->local_party_.T_;
    bc_message.pedersen_proof_ = ctx->local_party_.pedersen_proof_;
    bool ok = bc_message.ToBase64(out_bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in bc_message.ToBase64(out_bc_msg)!");
        return false;
    }

    return true;
}

}
}
}
}
