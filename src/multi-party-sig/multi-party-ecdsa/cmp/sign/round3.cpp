#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/security_param.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/round3.h"
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
using safeheron::zkp::pail::PailEncGroupEleRangeSetUp;
using safeheron::zkp::pail::PailEncGroupEleRangeWitness;
using safeheron::zkp::pail::PailEncGroupEleRangeStatement;
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

void Round3::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int j = 0; j < ctx->get_total_parties() - 1; ++j) {
        p2p_message_arr_.emplace_back();
    }
}

bool Round3::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

bool Round3::ReceiveVerify(const std::string &party_id) {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;
    const Curve * curv = ctx->GetCurrentCurve();

    int pos = sign_key.get_remote_party_pos(party_id);

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

    // Verify that according to \PI^{log*}
    // - K_j = enc_i(\k_j, \rho_j)
    // - \Delta_j = \Gamma_j * \k_j
    PailEncGroupEleRangeSetUp setup(sign_key.local_party_.N_,
                                      sign_key.local_party_.s_,
                                      sign_key.local_party_.t_);

    PailEncGroupEleRangeStatement statement(
            ctx->remote_parties_[pos].K_,
            ctx->remote_parties_[pos].pail_pub_.n(),
            ctx->remote_parties_[pos].pail_pub_.n_sqr(),
            curv->n,
            p2p_message_arr_[pos].Delta_,
            ctx->Gamma_,
            256, 512);

    p2p_message_arr_[pos].psi_double_prime_ij_.SetSalt(ctx->remote_parties_[pos].ssid_index_);
    ok = p2p_message_arr_[pos].psi_double_prime_ij_.Verify(setup, statement);
    if (!ok) {
        ctx->Identify(party_id, ctx->get_cur_round());
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in message_arr_[pos].psi_double_prime_ij_.Verify(setup, statement)");
        return false;
    }

    ctx->remote_parties_[pos].delta_ = p2p_message_arr_[pos].delta_;
    ctx->remote_parties_[pos].Delta_ = p2p_message_arr_[pos].Delta_;

    return true;
}

bool Round3::ComputeVerify() {
    bool ok = true;
    // Validate child private key share
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve * curv = ctx->GetCurrentCurve();

    // delta = Sum_i( delta_i )
    BN delta = ctx->local_party_.delta_;
    for (const auto & remote_party : ctx->remote_parties_) {
        delta = (delta + remote_party.delta_) % curv->n;
    }
    ctx->delta_ = delta;

    // Delta = Prod_i( Delta_i )
    CurvePoint Delta = ctx->local_party_.Delta_;
    for (const auto & remote_party : ctx->remote_parties_) {
        Delta = Delta + remote_party.Delta_;
    }
    // Verify g^\delta = \Prod_j{ \Delta_j }
    ok = (curv->g * delta == Delta);
    if (!ok) {
        ctx->Identify("", ctx->get_cur_round(), true);
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in (curv->g * delta == Delta)");
        return false;
    }

    // R = Gamma^(delta^-1 mod q)
    ctx->R_ = ctx->Gamma_ * delta.InvM(curv->n);

    ctx->r_ = ctx->R_.x() % curv->n;

    // sigma = k * m + r * chi  mod q
    ctx->local_party_.sigma_ = (ctx->local_party_.k_ * ctx->m_ + ctx->r_ * ctx->local_party_.chi_ ) % curv->n;

    return true;
}

bool Round3::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
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
        Round3P2PMessage p2p_message;
        p2p_message.ssid_ = ctx->ssid_;
        p2p_message.index_ = sign_key.local_party_.index_;
        p2p_message.sigma_ = ctx->local_party_.sigma_;
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

bool Round3::BuildProof() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve *curv = ctx->GetCurrentCurve();

    // (a) For l != i, party i reprove to party l that {D_{j,i}}_{j!=i,l} are well formed according to \PI^{aff-g}
    for (size_t l = 0; l < ctx->remote_parties_.size(); ++l) {
        safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V2 setup(sign_key.remote_parties_[l].N_,
                                                                 sign_key.remote_parties_[l].s_,
                                                                 sign_key.remote_parties_[l].t_);
        // For each j != i,l, prove {D_{j,i}}_{j!=i,l} are well formed
        for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
            if (j != l) {
                PailAffGroupEleRangeStatement_V2 statement(
                        ctx->remote_parties_[j].pail_pub_.n(),
                        ctx->remote_parties_[j].pail_pub_.n_sqr(),
                        ctx->local_party_.pail_pub_.n(),
                        ctx->local_party_.pail_pub_.n_sqr(),
                        ctx->remote_parties_[j].K_,
                        ctx->remote_parties_[j].D_ji,
                        ctx->remote_parties_[j].F_ji,
                        ctx->local_party_.Gamma_,
                        curv->n,
                        SECURITY_PARAM_L,
                        SECURITY_PARAM_L_PRIME,
                        SECURITY_PARAM_EPSILON);

                PailAffGroupEleRangeWitness_V2 witness(
                        ctx->local_party_.gamma_,
                        ctx->remote_parties_[j].beta_ij_.Neg(),
                        ctx->remote_parties_[j].s_ij_,
                        ctx->remote_parties_[j].r_ij_);

                PailAffGroupEleRangeProof_V2 proof;
                proof.SetSalt(ctx->local_party_.ssid_index_);
                proof.Prove(setup, statement, witness);
                ctx->proof_in_pre_sign_phase_.id_map_map_[sign_key.remote_parties_[l].party_id_][sign_key.remote_parties_[j].party_id_] = proof;
            }
        }
    }


    // (b) Compute H_i = Enc_i(k_i, gamma_i) and prove in ZK that H_i is well formed wrt K_i and G_i in \PI^{mul}
    // Sample rho in Z_N*
    BN rho = safeheron::rand::RandomBNLtCoPrime(sign_key.local_party_.N_);
    // c_k_gamma = G^k * rho^N  mod N^2
    BN c_k_gamma = (ctx->local_party_.G_.PowM(ctx->local_party_.k_, ctx->local_party_.pail_pub_.n_sqr())
                    * rho.PowM(ctx->local_party_.pail_pub_.n(), ctx->local_party_.pail_pub_.n_sqr())) %
                   ctx->local_party_.pail_pub_.n_sqr();
    PailEncMulStatement statement(
            ctx->local_party_.pail_pub_.n(),
            ctx->local_party_.pail_pub_.n_sqr(),
            ctx->local_party_.K_,
            ctx->local_party_.G_,
            c_k_gamma,
            curv->n);

    PailEncMulWitness witness(
            ctx->local_party_.k_,
            rho,
            ctx->local_party_.rho_);

    PailEncMulProof proof;
    proof.SetSalt(ctx->local_party_.ssid_index_);
    proof.Prove(statement, witness);
    ctx->proof_in_pre_sign_phase_.pail_enc_mul_proof_ = proof;
    ctx->proof_in_pre_sign_phase_.c_k_gamma_ = c_k_gamma;

    // (c) For l != i, prove in ZK that \delta is the plaintext value mod q of the cypher text obtained as
    //     H_i * \PI_{j!=i}{D_{i,j} * F_{j,i}} according to \PI^{dec}
    // Compute N^{-1} mod lambda(N)
    BN N_th_root = ctx->local_party_.pail_pub_.n().InvM(ctx->local_party_.pail_priv_.lambda());
    // Computer final_rho, raw_delta and c_deta that:
    //         - c_delta = Enc(raw_delta, final_rho) = H_i * \PI_{j!=i}{D_{i,j} * F_{j,i}}
    //         - raw_delta = delta mod q
    BN final_rho = ctx->local_party_.nu_.PowM(ctx->local_party_.k_, ctx->local_party_.pail_pub_.n_sqr());
    final_rho = ( final_rho * rho ) % ctx->local_party_.pail_pub_.n_sqr();
    BN c_deta = c_k_gamma;
    BN raw_delta = ctx->local_party_.k_ * ctx->local_party_.gamma_;
    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        BN t_rho = get_rho_in_pail_cypher(ctx->remote_parties_[j].recv_D_ij,
                                          ctx->remote_parties_[j].alpha_ij_,
                                          ctx->local_party_.pail_pub_.n(),
                                          ctx->local_party_.pail_pub_.n_sqr(),
                                          N_th_root);
        final_rho = (final_rho * t_rho) % ctx->local_party_.pail_pub_.n_sqr();
        final_rho = (final_rho * ctx->remote_parties_[j].r_ij_.InvM(ctx->local_party_.pail_pub_.n_sqr())) % ctx->local_party_.pail_pub_.n_sqr();

        c_deta = (c_deta * ctx->remote_parties_[j].recv_D_ij) % ctx->local_party_.pail_pub_.n_sqr();
        c_deta = (c_deta * ctx->remote_parties_[j].F_ji.InvM(ctx->local_party_.pail_pub_.n_sqr())) % ctx->local_party_.pail_pub_.n_sqr();

        raw_delta += ctx->remote_parties_[j].alpha_ij_ + ctx->remote_parties_[j].beta_ij_;
    }
    // prove that
    // - c_deta = Enc(raw_deta, rho)
    // - raw_delta = delta mod q
    for (size_t l = 0; l < ctx->remote_parties_.size(); ++l) {
        safeheron::zkp::pail::PailDecModuloSetUp setup(sign_key.remote_parties_[l].N_,
                                                       sign_key.remote_parties_[l].s_,
                                                       sign_key.remote_parties_[l].t_);
        zkp::pail::PailDecModuloStatement statement(
                curv->n,
                ctx->local_party_.pail_pub_.n(),
                ctx->local_party_.pail_pub_.n_sqr(),
                c_deta,
                ctx->local_party_.delta_,
                SECURITY_PARAM_L,
                SECURITY_PARAM_EPSILON);

        PailDecModuloWitness witness(
                raw_delta,
                final_rho);

        PailDecModuloProof proof;
        proof.SetSalt(ctx->local_party_.ssid_index_);
        proof.Prove(setup, statement, witness);
        ctx->proof_in_pre_sign_phase_.id_dec_proof_map_[sign_key.remote_parties_[l].party_id_] = proof;
    }

    return true;
}

bool Round3::VerifyProof(
        std::map<std::string, ProofInPreSignPhase> &map_proof,
        std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_D,
        std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_F) {
    bool ok = true;

    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const SignKey &sign_key = ctx->sign_key_;

    const safeheron::curve::Curve *curv = ctx->GetCurrentCurve();

    // In case of failure in Figure 7, do:
    for (auto &item_i: map_proof) {
        if((int)(item_i.second.id_map_map_.size() + 1) != ctx->get_total_parties()) return false;
        if((int)(item_i.second.id_dec_proof_map_.size() + 1) != ctx->get_total_parties()) return false;
        const std::string &party_id_i = item_i.first;
        if( !ctx->IsValidPartyID(party_id_i) ) return false;

        // (a) For l != i, party i reprove to party l that {D_{j,i}}_{j!=i,l} are well formed according to \PI^{aff-g}
        for (auto &item_l: item_i.second.id_map_map_) {
            if((int)(item_l.second.size() + 2) != ctx->get_total_parties()) return false;
            const std::string &party_id_l = item_l.first;
            if( !ctx->IsValidPartyID(party_id_l) ) return false;
            safeheron::zkp::pail::PailAffGroupEleRangeSetUp_V2 setup(ctx->GetN(party_id_l),
                                                                     ctx->GetS(party_id_l),
                                                                     ctx->GetT(party_id_l));
            // For each j != i,l, prove {D_{j,i}}_{j!=i,l} are well formed
            for (auto &item_j: item_l.second) {
                const std::string &party_id_j = item_j.first;
                if( !ctx->IsValidPartyID(party_id_j) ) return false;
                PailAffGroupEleRangeStatement_V2 statement(
                        ctx->GetPailPub(party_id_j).n(),
                        ctx->GetPailPub(party_id_j).n_sqr(),
                        ctx->GetPailPub(party_id_i).n(),
                        ctx->GetPailPub(party_id_i).n_sqr(),
                        ctx->GetK(party_id_j),
                        all_D.at(party_id_i).at(party_id_j),
                        all_F.at(party_id_i).at(party_id_j),
                        ctx->GetGamma(party_id_i),
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

        // (b) Compute H_i = Enc_i(k_i, gamma_i) and party i prove to party l in ZK that H_i is well formed wrt K_i and G_i in \PI^{mul}
        PailEncMulStatement statement(
                ctx->GetPailPub(party_id_i).n(),
                ctx->GetPailPub(party_id_i).n_sqr(),
                ctx->GetK(party_id_i),
                ctx->GetG(party_id_i),
                item_i.second.c_k_gamma_,
                curv->n);
        item_i.second.pail_enc_mul_proof_.SetSalt(ctx->GetSSIDIndex(party_id_i));
        ok = item_i.second.pail_enc_mul_proof_.Verify(statement);
        if (!ok) {
            ctx->identify_culprit_ = party_id_i;
            return false;
        }

        // (c) For l != i, party i prove to party j in ZK that \delta is the plaintext value mod q of the cypher text obtained as
        //     H_i * \PI_{j!=i}{D_{i,j} * F_{j,i}} according to \PI^{dec}
        // Computer raw_delta and c_deta that:
        //         - c_delta = Enc(raw_delta, final_rho) = H_i * \PI_{j!=i}{D_{i,j} * F_{j,i}}
        //         - raw_delta = delta mod q
        BN c_deta = item_i.second.c_k_gamma_;
        for (const auto &from: all_D) {
            for (const auto &to: from.second) {
                if (from.first != party_id_i && to.first == party_id_i) {
                    c_deta = (c_deta * to.second) % ctx->GetPailPub(party_id_i).n_sqr();
                }
            }
        }
        for (const auto &from: all_F) {
            for (const auto &to: from.second) {
                if (from.first == party_id_i && to.first != party_id_i) {
                    c_deta = (c_deta * to.second.InvM(ctx->GetPailPub(party_id_i).n_sqr())) % ctx->GetPailPub(party_id_i).n_sqr();
                }
            }
        }
        // prove that:
        // - c_deta = Enc(raw_deta, rho)
        // - raw_delta = delta mod q
        for (auto &item_l: item_i.second.id_dec_proof_map_) {
            const std::string &party_id_l = item_l.first;
            if( !ctx->IsValidPartyID(party_id_l) ) {
                ctx->identify_culprit_ = party_id_i;
                return false;
            }

            safeheron::zkp::pail::PailDecModuloSetUp setup(ctx->GetN(party_id_l),
                                                           ctx->GetS(party_id_l),
                                                           ctx->GetT(party_id_l));
            zkp::pail::PailDecModuloStatement statement(
                    curv->n,
                    ctx->GetPailPub(party_id_i).n(),
                    ctx->GetPailPub(party_id_i).n_sqr(),
                    c_deta,
                    ctx->GetDelta(party_id_i),
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
