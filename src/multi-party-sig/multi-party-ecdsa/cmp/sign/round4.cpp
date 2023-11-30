#include <vector>
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/security_param.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round4.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using safeheron::curve::Curve;
using safeheron::sss::Polynomial;
using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::zkp::pail::PailEncGroupEleRangeSetUp;
using safeheron::zkp::pail::PailEncGroupEleRangeStatement;
using safeheron::zkp::pail::PailEncGroupEleRangeWitness;
using safeheron::zkp::pail::PailEncGroupEleRangeProof;
using safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V2;
using safeheron::zkp::pail::PailAffGroupEleRangeStatement_V2;
using safeheron::zkp::pail::PailAffGroupEleRangeWitness_V2;
using safeheron::zkp::pail::PailAffGroupEleRangeProof_V2;
using safeheron::zkp::pail::PailEncMulStatement;
using safeheron::zkp::pail::PailEncMulWitness;
using safeheron::zkp::pail::PailEncMulProof;
using safeheron::zkp::pail::PailDecModuloSetUp;
using safeheron::zkp::pail::PailDecModuloStatement;
using safeheron::zkp::pail::PailDecModuloWitness;
using safeheron::zkp::pail::PailDecModuloProof;
using safeheron::zkp::pail::PailMulGroupEleRangeSetUp;
using safeheron::zkp::pail::PailMulGroupEleRangeStatement;
using safeheron::zkp::pail::PailMulGroupEleRangeWitness;
using safeheron::zkp::pail::PailMulGroupEleRangeProof;

static BN POW2_256 = BN(1) << 256;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

/*
 * Computer rho from cypher data:
 *   c = (1 + N)^m * rho^N  mod N_sqr
 * while N_th_root = N^-1 mod (p-1)*(q-1) and N = p*q
 */
static BN get_rho_in_pail_cypher(const BN& c, const BN& m, const BN& N, const BN& N_sqr, const BN& N_th_root){
    /*
    BN rho = (c * (m * N + 1).InvM(N_sqr)).PowM(N_th_root, N_sqr);
    BN c2 = ((m * N + 1) * rho.PowM(N, N_sqr)) % N_sqr;

    Note that c != c1 if the input (c, m, N, N_th_root) is not valid.
     */
    // rho = (c * (1 + N)^(-m))^N_th_root  mod N_sqr
    return (c * (m * N + 1).InvM(N_sqr)).PowM(N_th_root, N_sqr);
}


void Round4::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int j = 0; j < ctx->get_total_parties() - 1; ++j) {
        p2p_message_arr_.emplace_back();
    }
}

bool Round4::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

bool Round4::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

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

    ctx->remote_parties_[pos].sigma_ = p2p_message_arr_[pos].sigma_;

    return true;
}

bool Round4::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = ctx->GetCurrentCurve();

    // Recovery parameter
    uint32_t recovery_param = (ctx->R_.y().IsOdd() ? 1 : 0) |     // is_y_odd
                              ((ctx->R_.x() != ctx->r_) ? 2 : 0); // is_second_key

    BN s = ctx->local_party_.sigma_;
    for (auto & remote_party : ctx->remote_parties_) {
        s = (s + remote_party.sigma_) % curv->n;
    }
    s = s % curv->n;

    // Low S
    BN half_n = curv->n / 2;
    if (s > half_n){
        s = curv->n - s;
        recovery_param ^= 1;
    }
    ctx->s_ = s;
    ctx->v_ = recovery_param;

    // Verify the signature
    ok = safeheron::curve::ecdsa::VerifyPublicKey(sign_key.X_, sign_key.X_.GetCurveType(), ctx->m_, ctx->r_, ctx->s_, ctx->v_);
    if (!ok) {
        ctx->Identify("", ctx->get_cur_round(), false, true);
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to verify R,S,V with child public key!");
        return false;
    }

    return true;
}

bool Round4::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    return true;
}

bool Round4::BuildProof() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve *curv = ctx->GetCurrentCurve();

    // In case of failure in Figure 8, then retrieve the presigning transcript and do:
    // (a) For l != i, party i reprove to party l that {\hat{D}_{j,i}}_{j!=i,l} are well formed according to \PI^{aff-g}
    for (size_t l = 0; l < ctx->remote_parties_.size(); ++l) {
        safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V2 setup(sign_key.remote_parties_[l].N_,
                                                                 sign_key.remote_parties_[l].s_,
                                                                 sign_key.remote_parties_[l].t_);
        for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
            if (l != j) {
                PailAffGroupEleRangeStatement_V2 statement(
                        ctx->remote_parties_[j].pail_pub_.n(),
                        ctx->remote_parties_[j].pail_pub_.n_sqr(),
                        ctx->local_party_.pail_pub_.n(),
                        ctx->local_party_.pail_pub_.n_sqr(),
                        ctx->remote_parties_[j].K_,
                        ctx->remote_parties_[j].D_hat_ji,
                        ctx->remote_parties_[j].F_hat_ji,
                        sign_key.local_party_.X_,
                        curv->n,
                        SECURITY_PARAM_L,
                        SECURITY_PARAM_L_PRIME,
                        SECURITY_PARAM_EPSILON);

                PailAffGroupEleRangeWitness_V2 witness(
                        sign_key.local_party_.x_,
                        ctx->remote_parties_[j].beta_hat_ij_.Neg(),
                        ctx->remote_parties_[j].s_hat_ij_,
                        ctx->remote_parties_[j].r_hat_ij_);

                PailAffGroupEleRangeProof_V2 proof;
                proof.SetSalt(ctx->local_party_.ssid_index_);
                proof.Prove(setup, statement, witness);
                ctx->proof_in_sign_phase_.id_map_map_[sign_key.remote_parties_[l].party_id_][sign_key.remote_parties_[j].party_id_] = proof;
            }
        }
    }


    // (b) Compute H_i = Enc_i(k_i, x_i) and prove in ZK that \hat{H}_i is well formed wrt K_i and X_i in \PI^{mul*}
    // Sample rho in Z_N*
    BN rho = safeheron::rand::RandomBNLtCoPrime(sign_key.local_party_.N_);
    // c_k_x = K^x * rho^N  mod N^2
    BN c_k_x = (ctx->local_party_.K_.PowM(sign_key.local_party_.x_, ctx->local_party_.pail_pub_.n_sqr())
                    * rho.PowM(ctx->local_party_.pail_pub_.n(), ctx->local_party_.pail_pub_.n_sqr())) %
                   ctx->local_party_.pail_pub_.n_sqr();
    ctx->proof_in_sign_phase_.c_k_x_ = c_k_x;

    for (size_t l = 0; l < ctx->remote_parties_.size(); ++l) {
        PailMulGroupEleRangeSetUp setup(sign_key.remote_parties_[l].N_,
                                                       sign_key.remote_parties_[l].s_,
                                                       sign_key.remote_parties_[l].t_);
        PailMulGroupEleRangeStatement statement(
                ctx->local_party_.pail_pub_.n(),
                ctx->local_party_.pail_pub_.n_sqr(),
                ctx->local_party_.K_,
                c_k_x,
                sign_key.local_party_.X_,
                curv->g,
                curv->n,
                SECURITY_PARAM_L,
                SECURITY_PARAM_EPSILON);

        PailMulGroupEleRangeWitness witness(sign_key.local_party_.x_, rho);

        PailMulGroupEleRangeProof proof;
        proof.SetSalt(ctx->local_party_.ssid_index_);
        proof.Prove(setup, statement, witness);
        ctx->proof_in_sign_phase_.id_mul_group_ele_proof_map_[sign_key.remote_parties_[l].party_id_] = proof;

    }

    // (c) For l != i, prove in ZK that \sigma is the plaintext value mod q of the cypher text obtained as
    //     K_i^m * (\hat{H}_i * \PI_{j!=i}{\hat{D}_{i,j} * \hat{F}_{j,i}})^r according to \PI^{dec}
    // Compute N^{-1} mod lambda(N)
    BN N_th_root = ctx->local_party_.pail_pub_.n().InvM(ctx->local_party_.pail_priv_.lambda());
    // Computer final_rho, raw_delta and c_deta that:
    //         - c_sigma = Enc(raw_sigma, final_rho) = K_i^m * (\hat{H}_i * \PI_{j!=i}{\hat{D}_{i,j} * \hat{F}_{j,i}})^r
    //         - raw_sigma = sigma mod q
    BN final_rho = ctx->local_party_.rho_.PowM(sign_key.local_party_.x_, ctx->local_party_.pail_pub_.n_sqr());
    final_rho = ( final_rho * rho ) % ctx->local_party_.pail_pub_.n_sqr();
    BN c_chi = c_k_x;
    BN raw_chi = ctx->local_party_.k_ * sign_key.local_party_.x_;
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        BN t_rho = get_rho_in_pail_cypher(ctx->remote_parties_[j].recv_D_hat_ij,
                                          ctx->remote_parties_[j].alpha_hat_ij_,
                                          ctx->local_party_.pail_pub_.n(),
                                          ctx->local_party_.pail_pub_.n_sqr(),
                                          N_th_root);
        final_rho = (final_rho * t_rho) % ctx->local_party_.pail_pub_.n_sqr();
        final_rho = (final_rho * ctx->remote_parties_[j].r_hat_ij_.InvM(ctx->local_party_.pail_pub_.n_sqr())) % ctx->local_party_.pail_pub_.n_sqr();

        c_chi = (c_chi * ctx->remote_parties_[j].recv_D_hat_ij) % ctx->local_party_.pail_pub_.n_sqr();
        c_chi = (c_chi * ctx->remote_parties_[j].F_hat_ji.InvM(ctx->local_party_.pail_pub_.n_sqr())) % ctx->local_party_.pail_pub_.n_sqr();

        raw_chi += ctx->remote_parties_[j].alpha_hat_ij_ + ctx->remote_parties_[j].beta_hat_ij_;
    }

    BN r = ctx->R_.x();
    final_rho = ( ctx->local_party_.rho_.PowM(ctx->m_, ctx->local_party_.pail_pub_.n_sqr()) *
                  final_rho.PowM(r, ctx->local_party_.pail_pub_.n_sqr()) ) % ctx->local_party_.pail_pub_.n_sqr();
    BN c_sigma = ( ctx->local_party_.K_.PowM(ctx->m_, ctx->local_party_.pail_pub_.n_sqr()) *
                 c_chi.PowM(r, ctx->local_party_.pail_pub_.n_sqr()) ) % ctx->local_party_.pail_pub_.n_sqr();
    BN raw_sigma = ctx->local_party_.k_ * ctx->m_ + r * raw_chi;


    BN t_c_sigma = ( (raw_sigma * ctx->local_party_.pail_pub_.n() + 1) * final_rho.PowM(ctx->local_party_.pail_pub_.n(), ctx->local_party_.pail_pub_.n_sqr()) ) % ctx->local_party_.pail_pub_.n_sqr();

    // Prove that:
    //         - c_sigma = Enc(raw_sigma, final_rho) = K_i^m * (\hat{H}_i * \PI_{j!=i}{\hat{D}_{i,j} * \hat{F}_{j,i}})^r
    //         - raw_sigma = sigma mod q
    for (size_t l = 0; l < ctx->remote_parties_.size(); ++l) {
        safeheron::zkp::pail::PailDecModuloSetUp setup(sign_key.remote_parties_[l].N_,
                                                       sign_key.remote_parties_[l].s_,
                                                       sign_key.remote_parties_[l].t_);
        zkp::pail::PailDecModuloStatement statement(
                curv->n,
                ctx->local_party_.pail_pub_.n(),
                ctx->local_party_.pail_pub_.n_sqr(),
                c_sigma,
                ctx->local_party_.sigma_,
                SECURITY_PARAM_L,
                SECURITY_PARAM_EPSILON);

        PailDecModuloWitness witness(
                raw_sigma,
                final_rho);

        PailDecModuloProof proof;
        proof.SetSalt(ctx->local_party_.ssid_index_);
        proof.Prove(setup, statement, witness);
        ctx->proof_in_sign_phase_.id_dec_proof_map_[sign_key.remote_parties_[l].party_id_] = proof;
    }

    return true;
}

bool Round4::VerifyProof(
        std::map<std::string, ProofInSignPhase> &map_proof,
        std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_D_hat,
        std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_F_hat) {
    bool ok = true;

    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve *curv = ctx->GetCurrentCurve();

    // In case of failure in Figure 8, then retrieve the presigning transcript and do:
    // (a) For l != i, party i reprove to party l that {\hat{D}_{j,i}}_{j!=i,l} are well formed according to \PI^{aff-g}
    for (auto &item_i: map_proof) {
        const std::string &party_id_i = item_i.first;
        if( !ctx->IsValidPartyID(party_id_i) )
        {
            ctx->identify_culprit_ = party_id_i;
            return false;
        }
        if((int)item_i.second.id_map_map_.size() + 1 != ctx->get_total_parties()) {
            ctx->identify_culprit_ = party_id_i;
            return false;
        }
        if((int)item_i.second.id_dec_proof_map_.size() + 1 != ctx->get_total_parties()){
            ctx->identify_culprit_ = party_id_i;
            return false;
        }

        for (auto &item_l: item_i.second.id_map_map_) {
            if((int)(item_l.second.size() + 2) != ctx->get_total_parties()) {
                ctx->identify_culprit_ = party_id_i;
                return false;
            }
            const std::string &party_id_l = item_l.first;
            if( !ctx->IsValidPartyID(party_id_l) ) {
                ctx->identify_culprit_ = party_id_i;
                return false;
            }
            safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V2 setup(ctx->GetN(party_id_l),
                                                                     ctx->GetS(party_id_l),
                                                                     ctx->GetT(party_id_l));
            for (auto &item_j: item_l.second) {
                const std::string &party_id_j = item_j.first;
                if( !ctx->IsValidPartyID(party_id_j) ) {
                    ctx->identify_culprit_ = party_id_i;
                    return false;
                }
                PailAffGroupEleRangeStatement_V2 statement(
                        ctx->GetPailPub(party_id_j).n(),
                        ctx->GetPailPub(party_id_j).n_sqr(),
                        ctx->GetPailPub(party_id_i).n(),
                        ctx->GetPailPub(party_id_i).n_sqr(),
                        ctx->GetK(party_id_j),
                        all_D_hat.at(party_id_i).at(party_id_j),
                        all_F_hat.at(party_id_i).at(party_id_j),
                        ctx->GetX(party_id_i),
                        curv->n,
                        SECURITY_PARAM_L,
                        SECURITY_PARAM_L_PRIME,
                        SECURITY_PARAM_EPSILON);

                item_j.second.SetSalt(ctx->GetSSIDIndex(party_id_i));
                ok = item_j.second.Verify(setup, statement);
                if (!ok) {
                    ctx->identify_culprit_ = party_id_i;
                    return false;
                }
            }
        }

        // (b) Compute H_i = Enc_i(k_i, x_i) and prove in ZK that \hat{H}_i is well formed wrt K_i and X_i in \PI^{mul*}
        if((int)(item_i.second.id_mul_group_ele_proof_map_.size() + 1) != ctx->get_total_parties()) {
            ctx->identify_culprit_ = party_id_i;
            return false;
        }
        for (auto &item_l: item_i.second.id_mul_group_ele_proof_map_) {
            const std::string &party_id_l = item_l.first;
            if( !ctx->IsValidPartyID(party_id_l) ) {
                ctx->identify_culprit_ = party_id_i;
                return false;
            }

            PailMulGroupEleRangeSetUp setup(ctx->GetN(party_id_l),
                                                           ctx->GetS(party_id_l),
                                                           ctx->GetT(party_id_l));
            PailMulGroupEleRangeStatement statement(
                    ctx->GetPailPub(party_id_i).n(),
                    ctx->GetPailPub(party_id_i).n_sqr(),
                    ctx->GetK(party_id_i),
                    item_i.second.c_k_x_,
                    ctx->GetX(party_id_i),
                    curv->g,
                    curv->n,
                    SECURITY_PARAM_L,
                    SECURITY_PARAM_EPSILON);

            item_i.second.id_mul_group_ele_proof_map_.at(party_id_l).SetSalt(ctx->GetSSIDIndex(party_id_i));
            ok = item_i.second.id_mul_group_ele_proof_map_.at(party_id_l).Verify(setup, statement);
            if(!ok) {
                ctx->identify_culprit_ = party_id_i;
                return false;
            }
        }

        // (c) For l != i, prove in ZK that \sigma is the plaintext value mod q of the cypher text obtained as
        //     K_i^m * (\hat{H}_i * \PI_{j!=i}{\hat{D}_{i,j} * \hat{F}_{j,i}})^r according to \PI^{dec}
        BN c_chi = item_i.second.c_k_x_;
        for (const auto &from: all_D_hat) {
            for (const auto &to: from.second) {
                if (from.first != party_id_i && to.first == party_id_i) {
                    c_chi = (c_chi * to.second) % ctx->GetPailPub(party_id_i).n_sqr();
                }
            }
        }
        for (const auto &from: all_F_hat) {
            for (const auto &to: from.second) {
                if (from.first == party_id_i && to.first != party_id_i) {
                    c_chi = (c_chi * to.second.InvM(ctx->GetPailPub(party_id_i).n_sqr())) % ctx->GetPailPub(party_id_i).n_sqr();
                }
            }
        }
        BN r = ctx->R_.x();
        BN c_sigma = ( ctx->GetK(party_id_i).PowM(ctx->m_, ctx->GetPailPub(party_id_i).n_sqr()) *
                       c_chi.PowM(r, ctx->GetPailPub(party_id_i).n_sqr()) ) % ctx->GetPailPub(party_id_i).n_sqr();
        for (auto &item_l: item_i.second.id_dec_proof_map_) {
            const std::string &party_id_l = item_l.first;
            if( !ctx->IsValidPartyID(party_id_l) ) {
                ctx->identify_culprit_ = party_id_i;
                return false;
            }

            // Prove that:
            //         - c_sigma = Enc(raw_sigma, final_rho) = K_i^m * (\hat{H}_i * \PI_{j!=i}{\hat{D}_{i,j} * \hat{F}_{j,i}})^r
            //         - raw_sigma = sigma mod q
            safeheron::zkp::pail::PailDecModuloSetUp setup(ctx->GetN(party_id_l),
                                                           ctx->GetS(party_id_l),
                                                           ctx->GetT(party_id_l));
            zkp::pail::PailDecModuloStatement statement(
                    curv->n,
                    ctx->GetPailPub(party_id_i).n(),
                    ctx->GetPailPub(party_id_i).n_sqr(),
                    c_sigma,
                    ctx->GetSigma(party_id_i),
                    SECURITY_PARAM_L,
                    SECURITY_PARAM_EPSILON);

            item_l.second.SetSalt(ctx->GetSSIDIndex(party_id_i));
            ok = item_l.second.Verify(setup, statement);
            if (!ok) {
                ctx->identify_culprit_ = party_id_i;
                return false;
            }
        }
    }
    return true;
}


}
}
}
}
