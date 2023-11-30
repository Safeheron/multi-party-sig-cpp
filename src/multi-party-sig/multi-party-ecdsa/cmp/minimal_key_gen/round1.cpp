#include <cstdio>
#include "crypto-suites/crypto-sss/vsss.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/round1.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {

void Round1::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int j = 0; j < ctx->get_total_parties() - 1; ++j) {
        bc_message_arr_.emplace_back();
    }
}

bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;

    int pos = minimal_sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_arr_[pos].FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round1::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;
    bool ok = true;

    int pos = minimal_sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = compare_bytes(ctx->sid_, bc_message_arr_[pos].sid_) == 0;
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "compare_bytes(ctx->sid_, bc_message_arr_[pos].sid_) == 0");
        return false;
    }

    // save (index, V, rid)
    minimal_sign_key.remote_parties_[pos].index_ = bc_message_arr_[pos].index_;
    ctx->remote_parties_[pos].V_ = bc_message_arr_[pos].V_;

    return true;
}

bool Round1::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;

    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    bool ok = true;
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    MinimalSignKey &minimal_sign_key = ctx->minimal_sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        out_des_arr.push_back(minimal_sign_key.remote_parties_[j].party_id_);
    }

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        Round1P2PMessage p2p_message;
        p2p_message.sid_ = ctx->sid_;
        p2p_message.index_ = minimal_sign_key.local_party_.index_;
        p2p_message.x_ij_ = ctx->local_party_.map_party_id_x_[minimal_sign_key.remote_parties_[j].party_id_];
        string base64;
        bool ok = p2p_message.ToBase64(base64);
        if (!ok) {
            ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to encode to base64!");
            return false;
        }
        out_p2p_msg_arr.push_back(base64);
    }

    Round1BCMessage bc_message;
    bc_message.sid_ = ctx->sid_;
    bc_message.index_ = minimal_sign_key.local_party_.index_;
    bc_message.rid_ = ctx->local_party_.rid_;
    bc_message.X_ = ctx->local_party_.X_;
    bc_message.A_ = ctx->local_party_.A_;
    bc_message.B_ = ctx->local_party_.B_;
    bc_message.c_ = ctx->local_party_.c_;
    bc_message.map_party_id_X_ = ctx->local_party_.map_party_id_X_;
    bc_message.u_ = ctx->local_party_.u_;
    ok = bc_message.ToBase64(out_bc_msg);
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
