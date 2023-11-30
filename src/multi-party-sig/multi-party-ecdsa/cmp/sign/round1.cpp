
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/security_param.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round1.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/context.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::cmp::SignKey;
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

void Round1::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int j = 0; j < ctx->get_total_parties() - 1; ++j) {
        bc_message_arr_.emplace_back();
        p2p_message_arr_.emplace_back();
    }
}

bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    ok = p2p_message_arr_[pos].FromBase64(p2p_msg);
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round1::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = compare_bytes(ctx->ssid_, bc_message_arr_[pos].ssid_) == 0;
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in compare_bytes(ctx->ssid_, bc_message_arr_[pos].ssid_) == 0");
        return false;
    }

    ok = sign_key.remote_parties_[pos].index_ == bc_message_arr_[pos].index_;
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in sign_key.remote_parties_[pos].index_ == bc_message_arr_[pos].index_");
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
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in sign_key.remote_parties_[pos].index_ == p2p_message_arr_[pos].index_");
        return false;
    }

    // Verify that enc_j(\k_j, \rho_j)
    PailEncRangeSetUp_V2 setup(sign_key.local_party_.N_,
                               sign_key.local_party_.s_,
                               sign_key.local_party_.t_);

    PailEncRangeStatement_V2 statement(bc_message_arr_[pos].K_,
                                       ctx->remote_parties_[pos].pail_pub_.n(),
                                       ctx->remote_parties_[pos].pail_pub_.n_sqr(),
                                       curv->n,
                                       SECURITY_PARAM_L,
                                       SECURITY_PARAM_EPSILON);

    p2p_message_arr_[pos].psi_0_ij_.SetSalt(ctx->remote_parties_[pos].ssid_index_);
    ok = p2p_message_arr_[pos].psi_0_ij_.Verify(setup, statement);
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "message_arr_[pos].psi_0_ij_.Verify(setup, statement)");
        return false;
    }

    ctx->remote_parties_[pos].K_ = bc_message_arr_[pos].K_;
    ctx->remote_parties_[pos].G_ = bc_message_arr_[pos].G_;

    return true;
}

/**
 * - cypher_a = enc(remote_pub, a)
 * - cypher_alpha = a <hMul> b <hAdd> -beta
 *                = enc(remote_pub, alpha)
 * - cypher_beta = enc(local_pub, beta)
 *
 * @param remote_pub
 * @param local_pub
 * @param c_a
 * @param b
 * @param beta
 * @param r1_lt_coprime_remote_pail_n
 * @param r2_lt_coprime_local_pail_n
 * @param cypher_alpha
 * @param cypher_beta
 */
static void MTA_Step2(const pail::PailPubKey &remote_pub, const pail::PailPubKey &local_pub,
               const BN &cypher_a, const BN &b, const BN &beta,
               const BN &r1_lt_coprime_remote_pail_n,
               const BN &r2_lt_coprime_local_pail_n,
               BN &cypher_alpha,
               BN &cypher_beta){
    // cypher_alpha = a <hMul> b  <hAdd> negative_beta
    BN bma = remote_pub.HomomorphicMulPlain(cypher_a, b);
    cypher_alpha = remote_pub.HomomorphicAddPlainWithR(bma, beta.Neg(), r1_lt_coprime_remote_pail_n);
    cypher_beta = local_pub.EncryptNegWithR(beta.Neg(), r2_lt_coprime_local_pail_n);
}

bool Round1::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        // MTA(k, gamma) / MTA(k, x)
        // Sample r_ij, s_ij, \hat{r}_ij, \hat{s}_ij in Zn*
        ctx->remote_parties_[i].r_ij_ = safeheron::rand::RandomBNLtCoPrime(sign_key.local_party_.N_);
        ctx->remote_parties_[i].s_ij_ = safeheron::rand::RandomBNLtCoPrime(sign_key.remote_parties_[i].N_);
        ctx->remote_parties_[i].r_hat_ij_ = safeheron::rand::RandomBNLtCoPrime(sign_key.local_party_.N_);
        ctx->remote_parties_[i].s_hat_ij_ = safeheron::rand::RandomBNLtCoPrime(sign_key.remote_parties_[i].N_);

        // Sample \beta_ij, \hat{beta}_ij in limit_J
        ctx->remote_parties_[i].beta_ij_ = safeheron::rand::RandomNegBNInSymInterval(SECURITY_PARAM_LIMIT_J);
        ctx->remote_parties_[i].beta_hat_ij_ = safeheron::rand::RandomNegBNInSymInterval(SECURITY_PARAM_LIMIT_J);

        //MTA(k, gamma) - step 2
        // D_ji = (\gamma_i ☉ K_j ) ⨁ enc_j(-\beta_ij, s_ij)
        // F_ji = enc_i(-\beta_ij, r_ij)
        MTA_Step2(ctx->remote_parties_[i].pail_pub_,
                  ctx->local_party_.pail_pub_,
                  ctx->remote_parties_[i].K_,
                  ctx->local_party_.gamma_,
                  ctx->remote_parties_[i].beta_ij_,
                  ctx->remote_parties_[i].s_ij_,
                  ctx->remote_parties_[i].r_ij_,
                  ctx->remote_parties_[i].D_ji,
                  ctx->remote_parties_[i].F_ji);

        //MTA(k, x) - step 2
        // \hat{D}_ji = (\x_i ☉ K_j ) ⨁ enc_j(-\hat{\beta}_ij, \hat{s}_ij)
        // \hat{F}_ji = enc_i(-\hat{\beta}_ij, \hat{r}_ij)
        MTA_Step2(ctx->remote_parties_[i].pail_pub_,
                  ctx->local_party_.pail_pub_,
                  ctx->remote_parties_[i].K_,
                  sign_key.local_party_.x_,
                  ctx->remote_parties_[i].beta_hat_ij_,
                  ctx->remote_parties_[i].s_hat_ij_,
                  ctx->remote_parties_[i].r_hat_ij_,
                  ctx->remote_parties_[i].D_hat_ji,
                  ctx->remote_parties_[i].F_hat_ji);

        // - setup of proof in MTA
        PailAffGroupEleRangeSetUp_V2 setup(sign_key.remote_parties_[i].N_,
                                           sign_key.remote_parties_[i].s_,
                                           sign_key.remote_parties_[i].t_);

        // - Mta(k, gamma) step 2: bob proof
        // Prove that D_ji is well formed, according to \PI^{aff-g}
        PailAffGroupEleRangeStatement_V2 statement_1(
                ctx->remote_parties_[i].pail_pub_.n(),
                ctx->remote_parties_[i].pail_pub_.n_sqr(),
                ctx->local_party_.pail_pub_.n(),
                ctx->local_party_.pail_pub_.n_sqr(),
                ctx->remote_parties_[i].K_,
                ctx->remote_parties_[i].D_ji,
                ctx->remote_parties_[i].F_ji,
                ctx->local_party_.Gamma_,
                curv->n,
                SECURITY_PARAM_L,
                SECURITY_PARAM_L_PRIME,
                SECURITY_PARAM_EPSILON);

        PailAffGroupEleRangeWitness_V2 witness_1(
                ctx->local_party_.gamma_,
                ctx->remote_parties_[i].beta_ij_.Neg(),
                ctx->remote_parties_[i].s_ij_,
                ctx->remote_parties_[i].r_ij_);

        ctx->remote_parties_[i].psi_ji_.SetSalt(ctx->local_party_.ssid_index_);
        ctx->remote_parties_[i].psi_ji_.Prove(setup, statement_1, witness_1);

        // - Mta(k, x) step 2: bob proof
        // Prove that \hat{D}_ji is well formed, according to \PI^{aff-g}
        PailAffGroupEleRangeStatement_V2 statement_2(
                ctx->remote_parties_[i].pail_pub_.n(),
                ctx->remote_parties_[i].pail_pub_.n_sqr(),
                ctx->local_party_.pail_pub_.n(),
                ctx->local_party_.pail_pub_.n_sqr(),
                ctx->remote_parties_[i].K_,
                ctx->remote_parties_[i].D_hat_ji,
                ctx->remote_parties_[i].F_hat_ji,
                sign_key.local_party_.X_,
                curv->n,
                SECURITY_PARAM_L,
                SECURITY_PARAM_L_PRIME,
                SECURITY_PARAM_EPSILON);

        PailAffGroupEleRangeWitness_V2 witness_2(
                sign_key.local_party_.x_,
                ctx->remote_parties_[i].beta_hat_ij_.Neg(),
                ctx->remote_parties_[i].s_hat_ij_,
                ctx->remote_parties_[i].r_hat_ij_);

        ctx->remote_parties_[i].psi_hat_ji_.SetSalt(ctx->local_party_.ssid_index_);
        ctx->remote_parties_[i].psi_hat_ji_.Prove(setup, statement_2, witness_2);

        // Prove that according to \PI^{log*}
        // - G_i = enc_i(\gamma_i, \nu_i)
        // - \Gamma_i = g * \gamma_i
        PailEncGroupEleRangeSetUp setup_3(sign_key.remote_parties_[i].N_,
                                          sign_key.remote_parties_[i].s_,
                                          sign_key.remote_parties_[i].t_);

        PailEncGroupEleRangeStatement statement_3(
                ctx->local_party_.G_,
                ctx->local_party_.pail_pub_.n(),
                ctx->local_party_.pail_pub_.n_sqr(),
                curv->n,
                ctx->local_party_.Gamma_,
                curv->g,
                SECURITY_PARAM_L,
                SECURITY_PARAM_EPSILON);

        PailEncGroupEleRangeWitness witness_3(ctx->local_party_.gamma_, ctx->local_party_.nu_);

        ctx->remote_parties_[i].psi_prime_ji_.SetSalt(ctx->local_party_.ssid_index_);
        ctx->remote_parties_[i].psi_prime_ji_.Prove(setup_3, statement_3, witness_3);
    }

    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
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
        Round1P2PMessage p2p_message;
        p2p_message.ssid_ = ctx->ssid_;
        p2p_message.index_ = sign_key.local_party_.index_;
        p2p_message.Gamma_ = ctx->local_party_.Gamma_;
        p2p_message.D_ij_ = ctx->remote_parties_[j].D_ji;
        p2p_message.F_ij_ = ctx->remote_parties_[j].F_ji;
        p2p_message.D_hat_ij_ = ctx->remote_parties_[j].D_hat_ji;
        p2p_message.F_hat_ij_ = ctx->remote_parties_[j].F_hat_ji;
        p2p_message.psi_ij_ = ctx->remote_parties_[j].psi_ji_;
        p2p_message.psi_hat_ij_ = ctx->remote_parties_[j].psi_hat_ji_;
        p2p_message.psi_prime_ij_ = ctx->remote_parties_[j].psi_prime_ji_;
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
