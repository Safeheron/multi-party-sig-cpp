#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/util.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/round2.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/context.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {

bool Round2::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
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

bool Round2::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    if (p2p_message_.i_ != ctx->local_party_.j_
        || p2p_message_.j_ != ctx->local_party_.i_
        || p2p_message_.k_ != ctx->local_party_.k_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Inconsistent index.");
        return false;
    }

    bool ok = p2p_message_.phi_.Verify(p2p_message_.X_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in bc_message_.phi_.Verify(ctx->remote_parties_.X_)");
        return false;
    }
    if (p2p_message_.phi_.A_ != p2p_message_.R_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in (bc_message_.phi_.A_ == bc_message_.R_)");
        return false;
    }

    // Verify V_{j} = H(X_{j}, j, i, k, A_{j}, B_{j}, R_j, T_j , \phi_{j})
    safeheron::hash::CSafeHash256 sha256;
    uint8_t digest[safeheron::hash::CSafeHash256::OUTPUT_SIZE];

    std::string buf;
    p2p_message_.X_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    p2p_message_.i_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    p2p_message_.j_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    p2p_message_.k_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    p2p_message_.A_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    p2p_message_.R_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    p2p_message_.T_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    p2p_message_.phi_.ToBase64(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    sha256.Finalize(digest);
    std::string remote_V((const char*)digest, sizeof(digest));

    ok = compare_bytes(remote_V, ctx->remote_party_.V_j_) == 0;
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "compare_bytes(remote_V, ctx->remote_party_.V_j_) == 0");
        return false;
    }

    ctx->remote_party_.X_j_ = p2p_message_.X_;
    ctx->remote_party_.A_j_ = p2p_message_.A_;
    ctx->remote_party_.R_j_ = p2p_message_.R_;
    ctx->remote_party_.T_j_ = p2p_message_.T_;

    return true;
}

bool Round2::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(ctx->curve_type_);
    if (!curv) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ctx->curve_type_ is invalid!");
        return false;
    }

    safeheron::hash::CSHA256 sha256;
    uint8_t digest[safeheron::hash::CSHA256::OUTPUT_SIZE];

    // Compute \alpha = H((A_{j})^{a_{i}})
    std::string buf;
    safeheron::curve::CurvePoint p = ctx->remote_party_.A_j_ * ctx->local_party_.a_i_;
    p.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    sha256.Finalize(digest);
    safeheron::bignum::BN alpha = safeheron::bignum::BN::FromBytesBE(digest, sizeof(digest));
    alpha = alpha % curv->n;

    // Compute \Delta
    safeheron::bignum::BN delta = (ctx->local_party_.i_ > ctx->local_party_.j_) ? alpha : curv->n - alpha;

    const safeheron::bignum::BN& lambda_i = ctx->local_party_.l_arr_i_j_k_[0];
    const safeheron::bignum::BN& lambda_j = ctx->local_party_.l_arr_i_j_k_[1];
    const safeheron::bignum::BN& lambda_k = ctx->local_party_.l_arr_i_j_k_.back();
    const safeheron::bignum::BN& lambda_i_prime = ctx->local_party_.l_arr_i_j_[0];
    const safeheron::bignum::BN& lambda_j_prime = ctx->local_party_.l_arr_i_j_[1];
    // Compute X' = X_i^{\lambda^{\prime}_i } * X_j^{\lambda^{\prime}_j}
    ctx->local_party_.X_prime_ = ctx->local_party_.X_i_* lambda_i_prime + ctx->remote_party_.X_j_* lambda_j_prime;

    // Compute x_{k,i}^* = {\lambda^{\prime}}_{k}^{-1}*(\lambda_i^{\prime} - \lambda_i) * x
    safeheron::bignum::BN x_ki_star = lambda_k.InvM(curv->n) * ((lambda_i_prime - lambda_i) * ctx->x_i_);

    // Compute x_{k,i} = x_{k,i}^*  + \Delta \pmod q
    ctx->x_ki_ = (x_ki_star + delta) % curv->n;
    // Compute X_{k,i} = g^{x_{k,i}}
    ctx->local_party_.X_ki_ = curv->g * ctx->x_ki_;
    // Compute \psi_{i} = \mathcal{M}(prove, \Pi^{log}, (X_{k,i}); (x_{k,i}, t_i))
    ctx->local_party_.psi_i_.ProveWithREx(ctx->x_ki_, ctx->local_party_.t_i_, ctx->curve_type_);

    return true;
}

bool Round2::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                 std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    out_des_arr.push_back(ctx->remote_party_.party_id_);

    Round2P2PMessage p2p_message;
    p2p_message.X_ki_ = ctx->local_party_.X_ki_;
    p2p_message.psi_ = ctx->local_party_.psi_i_;

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


