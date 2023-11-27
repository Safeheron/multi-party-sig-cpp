#include "round2.h"
#include "context.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {
bool Round3::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    if(party_id != ctx->remote_party_.party_id_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Invalid party ID!");
        return false;
    }

    bool ok = bc_message_.FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round3::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    //if (bc_message_.S_.IsInfinity()) {
    //    ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "bc_message_.S_i_ is infinity.");
    //    return false;
    //}

    bool ok = bc_message_.psi_.Verify(bc_message_.S_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in bc_message_.psi_.Verify(bc_message_.S_i_)");
        return false;
    }

    if (bc_message_.psi_.A_ != ctx->remote_party_.T_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "Failed in (bc_message_.psi_.A_ != ctx->remote_parties_.T_)");
        return false;
    }

    ctx->remote_party_.S_ = bc_message_.S_;
    return true;
}

bool Round3::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(ctx->curve_type_);
    if (!curv) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ctx->curve_type_ is invalid!");
        return false;
    }

    ctx->X_k_ = ctx->local_party_.S_ + ctx->remote_party_.S_;

    safeheron::curve::CurvePoint X_1 = ctx->local_party_.X_ * ctx->local_party_.l_arr_i_k_[0] + ctx->X_k_ * ctx->local_party_.l_arr_i_k_[1];
    safeheron::curve::CurvePoint X_2 = ctx->local_party_.X_ * ctx->local_party_.l_arr_i_j_[0] +  ctx->remote_party_.X_ * ctx->local_party_.l_arr_i_j_[1];

    if (X_1 != X_2) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "X_1 != X_2");
        return false;
    }

    ctx->pub_ = X_1;

    return true;
}

bool Round3::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    // For final round, do nothing.
    return true;
}

}
}
}
}

