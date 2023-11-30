#include <cstdio>
#include "crypto-suites/crypto-sss/vsss.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/round1.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace aux_info_key_refresh {

void Round1::Init() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    for (int j = 0; j < ctx->get_total_parties() - 1; ++j) {
        bc_message_arr_.emplace_back();
    }
}

bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &minimal_sign_key = ctx->sign_key_;

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
    SignKey &sign_key = ctx->sign_key_;
    bool ok = true;

    int pos = sign_key.get_remote_party_pos(party_id);
    if (pos == -1) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    ok = compare_bytes(ctx->ssid_, bc_message_arr_[pos].ssid_) == 0;
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in compare_bytes(ctx->ssid_, bc_message_arr_[pos].ssid_) == 0");
        return false;
    }

    // save index
    ok = (sign_key.remote_parties_[pos].index_ == bc_message_arr_[pos].index_);
    if(!ok){
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "sign_key.remote_parties_[pos].index_ == message_arr_[pos].index_");
        return false;
    }

    // save V
    ctx->remote_parties_[pos].V_ = bc_message_arr_[pos].V_;

    return true;
}

bool Round1::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    SignKey &sign_key = ctx->sign_key_;

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    for (size_t j = 0; j < ctx->remote_parties_.size(); ++j) {
        out_des_arr.push_back(sign_key.remote_parties_[j].party_id_);
    }

    Round1BCMessage bc_message;
    bc_message.ssid_ = ctx->ssid_;
    bc_message.index_ = sign_key.local_party_.index_;
    bc_message.map_party_id_X_ = ctx->local_party_.map_party_id_X_;
    bc_message.map_party_id_A_ = ctx->local_party_.map_remote_party_id_A_;
    bc_message.c_ = ctx->local_party_.c_;
    bc_message.Y_ = sign_key.local_party_.Y_;
    bc_message.B_ = ctx->local_party_.B_;
    bc_message.N_ = sign_key.local_party_.N_;
    bc_message.s_ = sign_key.local_party_.s_;
    bc_message.t_ = sign_key.local_party_.t_;
    bc_message.psi_tilde_ = ctx->local_party_.psi_tilde_;
    bc_message.rho_ = ctx->local_party_.rho_;
    bc_message.u_ = ctx->local_party_.u_;
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
