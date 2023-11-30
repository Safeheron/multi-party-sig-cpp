#include <cstdio>
#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/context.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/round1.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_gen {

void Round1::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int i = 0; i < ctx->get_total_parties() - 1; ++i) {
        bc_message_arr_.emplace_back();
    }
}

bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize bc_message from base64!");
        return false;
    }

    return true;
}

bool Round1::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    bool ok = true;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = bc_message_arr_[pos].dln_proof_1_.Verify(bc_message_arr_[pos].N_tilde_,
                                               bc_message_arr_[pos].h1_,
                                               bc_message_arr_[pos].h2_);
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, string("Failed to verify DLN proof(dln_proof1_) from party :") + sign_key.remote_parties_[pos].party_id_);
        return false;
    }
    ok = bc_message_arr_[pos].dln_proof_2_.Verify(bc_message_arr_[pos].N_tilde_,
                                                  bc_message_arr_[pos].h2_,
                                                  bc_message_arr_[pos].h1_);
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, string("Failed to verify DLN proof(dln_proof2_) from party :") + sign_key.remote_parties_[pos].party_id_);
        return false;
    }
    sign_key.remote_parties_[pos].N_tilde_ = bc_message_arr_[pos].N_tilde_;
    sign_key.remote_parties_[pos].h1_ = bc_message_arr_[pos].h1_;
    sign_key.remote_parties_[pos].h2_ = bc_message_arr_[pos].h2_;

    sign_key.remote_parties_[pos].index_ = bc_message_arr_[pos].index_;

    sign_key.remote_parties_[pos].pail_pub_ = bc_message_arr_[pos].pail_pub_;

    ctx->remote_parties_[pos].kgc_y_ = bc_message_arr_[pos].kgc_y_;

    return true;
}

bool Round1::ComputeVerify() {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;
    const curve::Curve *curv = curve::GetCurveParam(ctx->curve_type_);

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        sign_key.remote_parties_[i].index_ = bc_message_arr_[i].index_;
        sign_key.remote_parties_[i].pail_pub_ = bc_message_arr_[i].pail_pub_;
    }

    // Sample coefficients in Z_n
    for(size_t i = 1; i < sign_key.threshold_; ++i){
        BN num = safeheron::rand::RandomBNLt(curv->n);
        ctx->local_party_.rand_polynomial_coe_arr_.push_back(num);
    }

    vector<BN> share_index_arr;
    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        share_index_arr.push_back(sign_key.remote_parties_[i].index_);
    }
    share_index_arr.push_back(sign_key.local_party_.index_);

    ok = CheckIndexArr(share_index_arr, curv->n);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in CheckIndexArr!");
        return false;
    }

    safeheron::sss::vsss::MakeSharesWithCommitsAndCoes(ctx->local_party_.share_points_,
                                                                 ctx->local_party_.vs_,
                                                                 ctx->local_party_.u_,
                                                                 (int)sign_key.threshold_,
                                                                 share_index_arr,
                                                                 ctx->local_party_.rand_polynomial_coe_arr_,
                                                                 curv->n,
                                                                 curv->g);

    // Last point belong to local party.
    sign_key.local_party_.x_ = ctx->local_party_.share_points_[share_index_arr.size() - 1].y;

    // No small factor proof
    for(size_t i = 0; i < sign_key.remote_parties_.size(); ++i){
        safeheron::zkp::no_small_factor_proof::NoSmallFactorSetUp set_up(sign_key.remote_parties_[i].N_tilde_,
                                                                         sign_key.remote_parties_[i].h1_,
                                                                         sign_key.remote_parties_[i].h2_);
        safeheron::zkp::no_small_factor_proof::NoSmallFactorStatement statement(sign_key.local_party_.pail_pub_.n(), 256, 512);
        safeheron::zkp::no_small_factor_proof::NoSmallFactorWitness witness(sign_key.local_party_.pail_priv_.p(), sign_key.local_party_.pail_priv_.q());
        ctx->remote_parties_[i].nsf_proof_.Prove(set_up, statement, witness);
    }

    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        out_des_arr.push_back(sign_key.remote_parties_[i].party_id_);
    }

    for (size_t i = 0; i < ctx->remote_parties_.size(); ++i) {
        Round1P2PMessage p2p_message;
        p2p_message.x_ij_ = ctx->local_party_.share_points_[i].y;
        p2p_message.nsf_proof_ = ctx->remote_parties_[i].nsf_proof_;
        string base64;
        bool ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    Round1BCMessage bc_message;
    bc_message.kgd_y_ = ctx->local_party_.kgd_y_;
    bc_message.vs_ = ctx->local_party_.vs_;
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
