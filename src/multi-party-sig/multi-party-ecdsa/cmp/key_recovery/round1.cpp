#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/round1.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/context.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {
bool Round1::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    if(party_id != ctx->remote_party_.party_id_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = p2p_message_.FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round1::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    ctx->remote_party_.V_j_ = p2p_message_.V_;

    return true;
}

bool Round1::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    return true;
}

bool Round1::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                 std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    out_des_arr.push_back(ctx->remote_party_.party_id_);

    Round1P2PMessage p2p_message;
    p2p_message.X_ = ctx->local_party_.X_i_;
    p2p_message.i_ = ctx->local_party_.i_;
    p2p_message.j_ = ctx->local_party_.j_;
    p2p_message.k_ = ctx->local_party_.k_;
    p2p_message.A_ = ctx->local_party_.A_i_;
    p2p_message.R_ = ctx->local_party_.R_i_;
    p2p_message.T_ = ctx->local_party_.T_i_;
    p2p_message.phi_ = ctx->local_party_.phi_i_;

    std::string base64;
    bool ok = p2p_message.ToBase64(base64);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in bc_message.ToBase64(out_bc_msg)!");
        return false;
    }
    out_p2p_msg_arr.push_back(base64);

    return true;
}

}
}
}
}

