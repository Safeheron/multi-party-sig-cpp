
#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/mta.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/round0.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/context.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::gg18::SignKey;
using safeheron::zkp::pail::PailEncRangeSetUp_V1;
using safeheron::zkp::pail::PailEncRangeStatement_V1;
using safeheron::zkp::pail::PailEncRangeProof_V1;
using safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V1;
using safeheron::zkp::pail::PailAffGroupEleRangeStatement_V1;
using safeheron::zkp::pail::PailAffGroupEleRangeProof_V1;
using safeheron::zkp::pail::PailEncGroupEleRangeSetUp;
using safeheron::zkp::pail::PailEncGroupEleRangeStatement;
using safeheron::zkp::pail::PailEncGroupEleRangeProof;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace sign{

bool Round0::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = GetCurveParam(sign_key.X_.GetCurveType());

    // Compute w = x * lambda mod q
    vector<BN> share_index_arr;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);
    vector<BN> &l_arr = ctx->local_party_.l_arr_;
    Polynomial::GetLArray(l_arr, BN::ZERO, share_index_arr, curv->n);
    ctx->local_party_.lambda_ = l_arr[share_index_arr.size()-1];
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        ctx->remote_parties_[i].lambda_ = l_arr[i];
    }
    ctx->local_party_.w_ = (sign_key.local_party_.x_ * ctx->local_party_.lambda_) % curv->n;

    // Sample k_i, gamma_i in Z_q
    ctx->local_party_.gamma_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.k_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.Gamma_ = curv->g * ctx->local_party_.gamma_;

    // Commitment(g_gamma_)
    ctx->local_party_.blind_factor_1_ = safeheron::rand::RandomBN(256);
    ctx->local_party_.commitment_Gamma_ = safeheron::commitment::CreateComWithBlind(ctx->local_party_.Gamma_, ctx->local_party_.blind_factor_1_);

    // MTA(k, gamma) / MTA(k, w) step1
    // - Constructor message A
    ctx->local_party_.r_for_pail_for_mta_msg_a_ = safeheron::rand::RandomBNLtCoPrime(sign_key.local_party_.pail_pub_.n());
    MtA_Step1(ctx->local_party_.message_a_,
              sign_key.local_party_.pail_pub_,
              ctx->local_party_.k_,
              ctx->local_party_.r_for_pail_for_mta_msg_a_);
    // - Generate proof from alice's side.
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        PailEncRangeSetUp_V1 setup(sign_key.remote_parties_[i].N_tilde_,
                                   sign_key.remote_parties_[i].h1_,
                                   sign_key.remote_parties_[i].h2_);

        PailEncRangeStatement_V1 statement(ctx->local_party_.message_a_,
                                           sign_key.local_party_.pail_pub_.n(),
                                           sign_key.local_party_.pail_pub_.n_sqr(),
                                           curv->n);
        zkp::pail::PailEncRangeWitness_V1 witness(ctx->local_party_.k_,
                                                  ctx->local_party_.r_for_pail_for_mta_msg_a_);
        ctx->remote_parties_[i].alice_proof_.Prove(setup, statement, witness);
    }
    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
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
        Round0P2PMessage p2p_message;
        p2p_message.alice_proof_ = ctx->remote_parties_[i].alice_proof_;
        string base64;
        bool ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    Round0BCMessage bc_message;
    bc_message.commitment_ = ctx->local_party_.commitment_Gamma_;
    bc_message.message_a_ = ctx->local_party_.message_a_;
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
