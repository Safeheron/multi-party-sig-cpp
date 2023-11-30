#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/round2.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/context.h"
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

    bool ok = p2p_message_.FromBase64(p2p_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round3::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    // \mathcal{M}(Verify, \Pi^{log}, (X_{k,j}), \psi_{j}) = 1
    bool ok = p2p_message_.psi_.Verify(p2p_message_.X_ki_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in bc_message_.psi_.Verify(bc_message_.S_i_)");
        return false;
    }

    if (p2p_message_.psi_.A_ != ctx->remote_party_.T_j_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__,
                           "Failed in (bc_message_.psi_.A_ != ctx->remote_parties_.T_)");
        return false;
    }

    ctx->remote_party_.X_kj_ = p2p_message_.X_ki_;
    return true;
}

bool Round3::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(ctx->curve_type_);
    if (!curv) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ctx->curve_type_ is invalid!");
        return false;
    }

    // Compute X_{k} = X_{k,i} * X_{k,j}
    ctx->X_k_ = ctx->local_party_.X_ki_ + ctx->remote_party_.X_kj_;

    const safeheron::bignum::BN& lambda_i = ctx->local_party_.l_arr_i_j_k_[0];
    const safeheron::bignum::BN& lambda_j = ctx->local_party_.l_arr_i_j_k_[1];
    const safeheron::bignum::BN& lambda_k = ctx->local_party_.l_arr_i_j_k_.back();

    // Compute X'' =  X_i^{\lambda_i} * X_j^{\lambda_j} * X_k^{\lambda_k}
    ctx->local_party_.X_double_prime_ = ctx->local_party_.X_i_ * lambda_i
                                      + ctx->remote_party_.X_j_ * lambda_j
                                      + ctx->X_k_ * lambda_k;

    // Verify X' = X''
    if (ctx->local_party_.X_prime_ != ctx->local_party_.X_double_prime_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "X' != X''");
        return false;
    }

    ctx->X_ = ctx->local_party_.X_prime_;

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

