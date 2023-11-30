#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/mta.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/round1.h"
#include "multi-party-sig/multi-party-ecdsa/gg20/sign/context.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::gg18::SignKey;
using safeheron::zkp::pail::PailEncRangeSetUp_V1;
using safeheron::zkp::pail::PailEncRangeStatement_V1;
using safeheron::zkp::pail::PailEncRangeProof_V1;
using safeheron::zkp::pail::PailAffRangeSetUp;
using safeheron::zkp::pail::PailAffRangeStatement;
using safeheron::zkp::pail::PailAffRangeWitness;
using safeheron::zkp::pail::PailAffRangeProof;
using safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V1;
using safeheron::zkp::pail::PailAffGroupEleRangeStatement_V1;
using safeheron::zkp::pail::PailAffGroupEleRangeWitness_V1;
using safeheron::zkp::pail::PailAffGroupEleRangeProof_V1;
using safeheron::multi_party_ecdsa::gg18::sign::MtA_Step2;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg20{
namespace sign{

void Round1::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
        p2p_message_arr_.emplace_back();
    }
}

bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round1::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ctx->remote_parties_[pos].com_Gamma_ = bc_message_arr_[pos].commitment_;

    PailEncRangeSetUp_V1 setup(sign_key.local_party_.N_tilde_,
                                sign_key.local_party_.h1_,
                                sign_key.local_party_.h2_);
    PailEncRangeStatement_V1 statement(bc_message_arr_[pos].message_a_,
                                       sign_key.remote_parties_[pos].pail_pub_.n(),
                                       sign_key.remote_parties_[pos].pail_pub_.n_sqr(),
                                       curv->n);
    ok = p2p_message_arr_[pos].alice_proof_.Verify(setup, statement);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify the 'alice_proof_'!");
        return false;
    }

    ctx->remote_parties_[pos].receive_message_a_ = bc_message_arr_[pos].message_a_;

    return true;
}

bool Round1::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());
    BN q2 = curv->n * curv->n;
    BN q5 = q2 * q2 * curv->n;

    for (size_t i = 0; i < sign_key.remote_parties_.size(); ++i) {
        // MTA(k, gamma) / MTA(k, w)

        // - Mta(k, gamma) step 2: construct message b
        //      - Sample beta_tag in q^5
        //      - Sample r in (0, N)
        ctx->remote_parties_[i].beta_tag_for_mta_k_gamma_msg_b_ = safeheron::rand::RandomBNLt(q5);
        ctx->remote_parties_[i].r_for_pail_for_mta_k_gamma_msg_b_ = safeheron::rand::RandomBNLtCoPrime(sign_key.remote_parties_[i].pail_pub_.n());

        MtA_Step2(ctx->remote_parties_[i].message_b_for_k_gamma_,
                ctx->remote_parties_[i].beta_for_k_gamma_,
                sign_key.remote_parties_[i].pail_pub_,
                ctx->local_party_.gamma_,
                bc_message_arr_[i].message_a_,
                ctx->remote_parties_[i].beta_tag_for_mta_k_gamma_msg_b_,
                ctx->remote_parties_[i].r_for_pail_for_mta_k_gamma_msg_b_,
                curv->n);

        // - Mta(k, gamma) step 2: bob proof
        PailAffRangeSetUp setup_1(sign_key.remote_parties_[i].N_tilde_,
                                sign_key.remote_parties_[i].h1_,
                                sign_key.remote_parties_[i].h2_);
        PailAffRangeStatement statement_1(bc_message_arr_[i].message_a_,
                                          ctx->remote_parties_[i].message_b_for_k_gamma_,
                                          sign_key.remote_parties_[i].pail_pub_,
                                          curv->n);
        PailAffRangeWitness witness_1(ctx->local_party_.gamma_,
                                      ctx->remote_parties_[i].beta_tag_for_mta_k_gamma_msg_b_,
                                      ctx->remote_parties_[i].r_for_pail_for_mta_k_gamma_msg_b_);
        ctx->remote_parties_[i].bob_proof_1_.Prove(setup_1, statement_1, witness_1);

        // - Mta(k, w) step 2: construct message b
        //      - Sample beta_tag in q^5
        //      - Sample r in (0, N)
        ctx->remote_parties_[i].beta_tag_for_mta_k_w_msg_b_ = safeheron::rand::RandomBNLt(q5);
        ctx->remote_parties_[i].r_for_pail_for_mta_k_w_msg_b_ = safeheron::rand::RandomBNLtCoPrime(sign_key.remote_parties_[i].pail_pub_.n());
        MtA_Step2(ctx->remote_parties_[i].message_b_for_k_w_,
                ctx->remote_parties_[i].beta_for_k_w_,
                sign_key.remote_parties_[i].pail_pub_,
                ctx->local_party_.w_,
                bc_message_arr_[i].message_a_,
                ctx->remote_parties_[i].beta_tag_for_mta_k_w_msg_b_,
                ctx->remote_parties_[i].r_for_pail_for_mta_k_w_msg_b_,
                curv->n);

        // - Mta(k, w) step 2: bob proof
        PailAffGroupEleRangeSetUp_V1 setup_2(sign_key.remote_parties_[i].N_tilde_,
                                             sign_key.remote_parties_[i].h1_,
                                             sign_key.remote_parties_[i].h2_);
        PailAffGroupEleRangeStatement_V1 statement_2(bc_message_arr_[i].message_a_,
                                          ctx->remote_parties_[i].message_b_for_k_w_,
                                          sign_key.remote_parties_[i].pail_pub_,
                                          sign_key.local_party_.g_x_ * ctx->local_party_.l_arr_.back(),
                                          curv->n);
        PailAffGroupEleRangeWitness_V1 witness_2(ctx->local_party_.w_,
                                      ctx->remote_parties_[i].beta_tag_for_mta_k_w_msg_b_,
                                      ctx->remote_parties_[i].r_for_pail_for_mta_k_w_msg_b_);
        ctx->remote_parties_[i].bob_proof_2_.Prove(setup_2, statement_2, witness_2);

    }

    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Round1P2PMessage p2p_message;
        p2p_message.message_b_for_k_gamma_ = ctx->remote_parties_[i].message_b_for_k_gamma_;
        p2p_message.message_b_for_k_w_ = ctx->remote_parties_[i].message_b_for_k_w_;
        p2p_message.bob_proof_1_ = ctx->remote_parties_[i].bob_proof_1_;
        p2p_message.bob_proof_2_ = ctx->remote_parties_[i].bob_proof_2_;
        string base64;
        bool ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    return true;
}

}
}
}
}
