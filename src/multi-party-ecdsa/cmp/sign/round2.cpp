
#include "round2.h"
#include "context.h"
#include "crypto-commitment/commitment.h"
#include "crypto-curve/curve.h"
#include "crypto-zkp/pedersen_proof.h"
#include "crypto-bn/rand.h"
#include "crypto-hash/sha256.h"
#include "crypto-encode/hex.h"
#include "security_param.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::zkp::pedersen_proof::PedersenStatement;
using safeheron::zkp::pedersen_proof::PedersenWitness;
using safeheron::zkp::pedersen_proof::PedersenProof;
using safeheron::hash::CSHA256;
using safeheron::zkp::pail::PailAffRangeSetUp;
using safeheron::zkp::pail::PailAffRangeStatement;
using safeheron::zkp::pail::PailAffRangeWitness;
using safeheron::zkp::pail::PailAffRangeProof;
using safeheron::zkp::pedersen_proof::PedersenStatement;
using safeheron::zkp::pedersen_proof::PedersenWitness;
using safeheron::zkp::pedersen_proof::PedersenProof;
using safeheron::zkp::pail::PailEncRangeSetUp_V2;
using safeheron::zkp::pail::PailEncRangeStatement_V2;
using safeheron::zkp::pail::PailEncRangeWitness_V2;
using safeheron::zkp::pail::PailEncRangeProof_V2;
using safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V2;
using safeheron::zkp::pail::PailAffGroupEleRangeStatement_V2;
using safeheron::zkp::pail::PailAffGroupEleRangeWitness_V2;
using safeheron::zkp::pail::PailAffGroupEleRangeProof_V2;
using safeheron::zkp::pail::PailEncGroupEleRangeSetUp;
using safeheron::zkp::pail::PailEncGroupEleRangeWitness;
using safeheron::zkp::pail::PailEncGroupEleRangeStatement;
using safeheron::zkp::pail::PailEncGroupEleRangeProof;
using safeheron::zkp::pail::PailAffRangeSetUp;
using safeheron::zkp::pail::PailAffRangeStatement;
using safeheron::zkp::pail::PailAffRangeProof;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

void Round2::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        p2p_message_arr_.emplace_back();
    }
}

bool Round2::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    // bool ok = message_arr_[pos].FromBase64(msg);
    bool ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round2::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = ctx->ssid_ == p2p_message_arr_[pos].ssid_;
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in ctx->ssid_ == message_arr_[pos].ssid_");
        return false;
    }

    ok = sign_key.remote_parties_[pos].index_ == p2p_message_arr_[pos].index_;
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in sign_key.remote_parties_[pos].index_ == message_arr_[pos].index_");
        return false;
    }

    // - setup of proof in MTA
    PailAffGroupEleRangeSetUp_V2 setup(sign_key.local_party_.N_,
                                       sign_key.local_party_.s_,
                                       sign_key.local_party_.t_);

    // - Mta(k, gamma) step 2: bob proof
    PailAffGroupEleRangeStatement_V2 statement_1(
            ctx->local_party_.pail_pub_.n(),
            ctx->local_party_.pail_pub_.n_sqr(),
            ctx->remote_parties_[pos].pail_pub_.n(),
            ctx->remote_parties_[pos].pail_pub_.n_sqr(),
            ctx->local_party_.K_,
            p2p_message_arr_[pos].D_ij_,
            p2p_message_arr_[pos].F_ij_,
            p2p_message_arr_[pos].Gamma_,
            curv->n,
            SECURITY_PARAM_L,
            SECURITY_PARAM_L_PRIME,
            SECURITY_PARAM_EPSILON);

    ok = p2p_message_arr_[pos].psi_ij_.Verify(setup, statement_1);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in message_arr_[pos].psi_ij_.Verify(setup, statement_1)");
        return false;
    }

    // - Mta(k, x) step 2: bob proof
    PailAffGroupEleRangeStatement_V2 statement_2(
            ctx->local_party_.pail_pub_.n(),
            ctx->local_party_.pail_pub_.n_sqr(),
            ctx->remote_parties_[pos].pail_pub_.n(),
            ctx->remote_parties_[pos].pail_pub_.n_sqr(),
            ctx->local_party_.K_,
            p2p_message_arr_[pos].D_hat_ij_,
            p2p_message_arr_[pos].F_hat_ij_,
            sign_key.remote_parties_[pos].X_,
            curv->n,
            SECURITY_PARAM_L,
            SECURITY_PARAM_L_PRIME,
            SECURITY_PARAM_EPSILON);

    ok = p2p_message_arr_[pos].psi_hat_ij_.Verify(setup, statement_2);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in message_arr_[pos].psi_hat_ij_.Verify(setup, statement_2)");
        return false;
    }

    PailEncGroupEleRangeSetUp setup_3(sign_key.local_party_.N_,
                                      sign_key.local_party_.s_,
                                      sign_key.local_party_.t_);

    PailEncGroupEleRangeStatement statement_3(
            ctx->remote_parties_[pos].G_,
            ctx->remote_parties_[pos].pail_pub_.n(),
            ctx->remote_parties_[pos].pail_pub_.n_sqr(),
            curv->n,
            p2p_message_arr_[pos].Gamma_,
            curv->g,
            SECURITY_PARAM_L,
            SECURITY_PARAM_EPSILON);

    ok = p2p_message_arr_[pos].psi_prime_ij_.Verify(setup_3, statement_3);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in message_arr_[pos].psi_prime_ij_.Verify(setup_3, statement_3)");
        return false;
    }

    ctx->remote_parties_[pos].Gamma_ = p2p_message_arr_[pos].Gamma_;

    return true;
}

bool Round2::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
    }

    CurvePoint Gamma = ctx->local_party_.Gamma_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Gamma += ctx->remote_parties_[i].Gamma_;
    }
    ctx->Gamma_ = Gamma;

    ctx->local_party_.Delta_ = Gamma * ctx->local_party_.k_;

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        // alpha_ij = dec(D_ij)
        ctx->remote_parties_[i].alpha_ij_ = ctx->local_party_.pail_priv_.DecryptNeg(p2p_message_arr_[i].D_ij_);
        // alpha_hat_ij = dec(D_hat_ij)
        ctx->remote_parties_[i].alpha_hat_ij_ = ctx->local_party_.pail_priv_.DecryptNeg(p2p_message_arr_[i].D_hat_ij_);

        // delta = gamma * k + Sum_{i!=j}{alpha_ij + beta_ij}
        BN delta = ctx->local_party_.gamma_ * ctx->local_party_.k_;
        for (const auto & remote_party : ctx->remote_parties_) {
            delta = (delta + remote_party.alpha_ij_ + remote_party.beta_ij_) % curv->n;
        }
        ctx->local_party_.delta_ = delta;

        // chi = x * k + Sum_{i!=j}{alpha_hat_ij + beta_hat_ij}
        BN chi = sign_key.local_party_.x_ * ctx->local_party_.k_;
        for (const auto & remote_party : ctx->remote_parties_) {
            chi = (chi + remote_party.alpha_hat_ij_ + remote_party.beta_hat_ij_) % curv->n;
        }
        ctx->local_party_.chi_ = chi;

        PailEncGroupEleRangeSetUp setup(sign_key.remote_parties_[i].N_,
                                          sign_key.remote_parties_[i].s_,
                                          sign_key.remote_parties_[i].t_);

        PailEncGroupEleRangeStatement statement(
                ctx->local_party_.K_,
                ctx->local_party_.pail_pub_.n(),
                ctx->local_party_.pail_pub_.n_sqr(),
                curv->n,
                ctx->local_party_.Delta_,
                ctx->Gamma_,
                SECURITY_PARAM_L,
                SECURITY_PARAM_EPSILON);

        PailEncGroupEleRangeWitness witness(ctx->local_party_.k_, ctx->local_party_.rho_);

        ctx->remote_parties_[i].psi_double_prime_ij_.Prove(setup, statement, witness);
    }

    return true;
}

bool Round2::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Round2P2PMessage p2p_message;
        p2p_message.ssid_ = ctx->ssid_;
        p2p_message.index_ = sign_key.local_party_.index_;
        p2p_message.delta_ = ctx->local_party_.delta_;
        p2p_message.Delta_ = ctx->local_party_.Delta_;
        p2p_message.psi_double_prime_ij_ = ctx->remote_parties_[i].psi_double_prime_ij_;
        string base64;
        ok = p2p_message.ToBase64(base64);
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
