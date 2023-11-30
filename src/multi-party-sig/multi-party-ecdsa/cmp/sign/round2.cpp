#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/pedersen_proof.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/security_param.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round2.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/context.h"

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
using safeheron::hash::CSafeHash256;
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
    for (int j = 0; j < ctx->get_total_parties() - 1; ++j) {
        p2p_message_arr_.emplace_back();
    }
}

bool Round2::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    // bool ok = message_arr_[pos].FromBase64(msg);
    bool ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
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
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = compare_bytes(ctx->ssid_, p2p_message_arr_[pos].ssid_) == 0;
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in compare_bytes(ctx->ssid_, p2p_message_arr_[pos].ssid_) == 0");
        return false;
    }

    ok = sign_key.remote_parties_[pos].index_ == p2p_message_arr_[pos].index_;
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in sign_key.remote_parties_[pos].index_ == message_arr_[pos].index_");
        return false;
    }

    // - setup of proof in MTA
    PailAffGroupEleRangeSetUp_V2 setup(sign_key.local_party_.N_,
                                       sign_key.local_party_.s_,
                                       sign_key.local_party_.t_);

    // - Mta(k, gamma) step 2: bob proof
    // Prove that D_ij is well formed, according to \PI^{aff-g}
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

    p2p_message_arr_[pos].psi_ij_.SetSalt(ctx->remote_parties_[pos].ssid_index_);
    ok = p2p_message_arr_[pos].psi_ij_.Verify(setup, statement_1);
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in message_arr_[pos].psi_ij_.Verify(setup, statement_1)");
        return false;
    }

    // - Mta(k, x) step 2: bob proof
    // Prove that \hat{D}_ji is well formed, according to \PI^{aff-g}
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

    p2p_message_arr_[pos].psi_hat_ij_.SetSalt(ctx->remote_parties_[pos].ssid_index_);
    ok = p2p_message_arr_[pos].psi_hat_ij_.Verify(setup, statement_2);
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in message_arr_[pos].psi_hat_ij_.Verify(setup, statement_2)");
        return false;
    }

    // Verify that according to \PI^{log*}
    // - G_j = enc_j(\gamma_j, \nu_j)
    // - \Gamma_j = g * \gamma_j
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

    p2p_message_arr_[pos].psi_prime_ij_.SetSalt(ctx->remote_parties_[pos].ssid_index_);
    ok = p2p_message_arr_[pos].psi_prime_ij_.Verify(setup_3, statement_3);
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in message_arr_[pos].psi_prime_ij_.Verify(setup_3, statement_3)");
        return false;
    }

    ctx->remote_parties_[pos].Gamma_ = p2p_message_arr_[pos].Gamma_;
    ctx->remote_parties_[pos].recv_D_ij = p2p_message_arr_[pos].D_ij_;
    ctx->remote_parties_[pos].recv_F_ij = p2p_message_arr_[pos].F_ij_;
    ctx->remote_parties_[pos].recv_D_hat_ij = p2p_message_arr_[pos].D_hat_ij_;
    ctx->remote_parties_[pos].recv_F_hat_ij = p2p_message_arr_[pos].F_hat_ij_;

    return true;
}

bool Round2::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    // set \Gamma = \Prod_j{\Gamma_j}
    CurvePoint Gamma = ctx->local_party_.Gamma_;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Gamma += ctx->remote_parties_[i].Gamma_;
    }
    ctx->Gamma_ = Gamma;

    // set \Deta_i = \Gamma^k_i
    ctx->local_party_.Delta_ = Gamma * ctx->local_party_.k_;

    // For every j != i, set
    // - \alpha_ij = dec_i{D_ij}
    // - \hat{\alpha}_ij = dec_i{\hat{D}_ij}
    // - \delta_i = \gamma_i * \k_i + \Sum_{j!=i}{ \alpha_ij       + \beta_ij        }     mod q
    // - \chi_i   = x_i      * \k_i + \Sum_{j!=i}{ \hat{\alpha}_ij + \hat{\beta}_ij  }     mod q
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        // \alpha_ij = dec_i{D_ij}
        ctx->remote_parties_[j].alpha_ij_ = ctx->local_party_.pail_priv_.DecryptNeg(p2p_message_arr_[j].D_ij_);
        // \hat{\alpha}_ij = dec_i{\hat{D}_ij}
        ctx->remote_parties_[j].alpha_hat_ij_ = ctx->local_party_.pail_priv_.DecryptNeg(p2p_message_arr_[j].D_hat_ij_);
    }

    // \delta_i = \gamma_i * \k_i + \Sum_{j!=i}{ \alpha_ij + \beta_ij }     mod q
    BN delta = ctx->local_party_.gamma_ * ctx->local_party_.k_;
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        delta = (delta + ctx->remote_parties_[j].alpha_ij_ + ctx->remote_parties_[j].beta_ij_) % curv->n;
    }
    ctx->local_party_.delta_ = delta;

    // \chi_i = x_i * \k_i + \Sum_{j!=i}{ \hat{\alpha}_ij + \hat{\beta}_ij  }     mod q
    BN chi = sign_key.local_party_.x_ * ctx->local_party_.k_;
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        chi = (chi + ctx->remote_parties_[j].alpha_hat_ij_ + ctx->remote_parties_[j].beta_hat_ij_) % curv->n;
    }
    ctx->local_party_.chi_ = chi;

    // For j != i, party i prove to party j that according to \PI^{log*}
    // - K_i = enc_i(\k_i, \rho_i)
    // - \Delta_i = \Gamma_i * \k_i
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        PailEncGroupEleRangeSetUp setup(sign_key.remote_parties_[j].N_,
                                          sign_key.remote_parties_[j].s_,
                                          sign_key.remote_parties_[j].t_);

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

        ctx->remote_parties_[j].psi_double_prime_ji_.SetSalt(ctx->local_party_.ssid_index_);
        ctx->remote_parties_[j].psi_double_prime_ji_.Prove(setup, statement, witness);
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

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        out_des_arr.push_back(sign_key.remote_parties_[j].party_id_);
    }

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        Round2P2PMessage p2p_message;
        p2p_message.ssid_ = ctx->ssid_;
        p2p_message.index_ = sign_key.local_party_.index_;
        p2p_message.delta_ = ctx->local_party_.delta_;
        p2p_message.Delta_ = ctx->local_party_.Delta_;
        p2p_message.psi_double_prime_ij_ = ctx->remote_parties_[j].psi_double_prime_ji_;
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
