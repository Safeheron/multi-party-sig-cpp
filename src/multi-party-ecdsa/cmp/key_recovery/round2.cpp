#include "round2.h"
#include "context.h"
#include "crypto-hash/sha256.h"
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

    bool ok = bc_message_.FromBase64(bc_msg);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to deserialize from base64!");
        return false;
    }

    return true;
}

bool Round2::ReceiveVerify(const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    if (bc_message_.i_ != ctx->local_party_.j_
        || bc_message_.j_ != ctx->local_party_.i_
        || bc_message_.k_ != ctx->local_party_.k_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Inconsistent index.");
        return false;
    }

    //if (bc_message_.X_.IsInfinity()) {
    //    ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "bc_message_.X_ is infinity.");
    //    return false;
    //}

    bool ok = bc_message_.phi_.Verify(bc_message_.X_);
    if (!ok) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in bc_message_.phi_.Verify(ctx->remote_parties_.X_)");
        return false;
    }
    if (bc_message_.phi_.A_ != bc_message_.R_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed in (bc_message_.phi_.A_ == bc_message_.R_)");
        return false;
    }

    safeheron::hash::CSHA256 sha256;
    uint8_t digest[safeheron::hash::CSHA256::OUTPUT_SIZE];

    std::string buf;
    bc_message_.X_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_.X_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    bc_message_.i_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_.j_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_.k_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    bc_message_.A_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_.A_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    bc_message_.B_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_.B_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    bc_message_.R_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_.R_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    bc_message_.T_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    bc_message_.T_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    bc_message_.phi_.ToBase64(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    sha256.Finalize(digest);
    std::string remote_V((const char*)digest, sizeof(digest));

    if (remote_V != ctx->remote_party_.V_) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "remote_V != ctx->remote_parties_.V_!");
        return false;
    }

    ctx->remote_party_.X_ = bc_message_.X_;
    ctx->remote_party_.i_ = bc_message_.i_;
    ctx->remote_party_.j_ = bc_message_.j_;
    ctx->remote_party_.k_ = bc_message_.k_;
    ctx->remote_party_.A_ = bc_message_.A_;
    ctx->remote_party_.B_ = bc_message_.B_;
    ctx->remote_party_.R_ = bc_message_.R_;
    ctx->remote_party_.T_ = bc_message_.T_;

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

    std::string buf;
    safeheron::curve::CurvePoint p_1 = ctx->remote_party_.B_ * ctx->local_party_.a_;
    p_1.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    p_1.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    sha256.Finalize(digest);
    safeheron::bignum::BN alpha = safeheron::bignum::BN::FromBytesBE(digest, sizeof(digest));

    safeheron::curve::CurvePoint p_2 = ctx->remote_party_.A_ * ctx->local_party_.b_;
    sha256.Reset();
    p_2.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    p_2.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    sha256.Finalize(digest);
    safeheron::bignum::BN beta = safeheron::bignum::BN::FromBytesBE(digest, sizeof(digest));

    safeheron::bignum::BN lambda_k = ctx->local_party_.l_arr_.back();
    safeheron::bignum::BN lambda_i_1 = ctx->local_party_.l_arr_i_j_[0];
    safeheron::bignum::BN lambda_i_2 = ctx->local_party_.l_arr_[0];
    safeheron::bignum::BN s = lambda_k.InvM(curv->n) * ((lambda_i_1 - lambda_i_2) * ctx->x_);
    ctx->s_ = (s + alpha - beta) % curv->n;

    ctx->local_party_.S_ = curv->g * ctx->s_;
    ctx->local_party_.psi_.ProveWithREx(ctx->s_, ctx->local_party_.t_, ctx->curve_type_);

    return true;
}

bool Round2::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                 std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    out_des_arr.push_back(ctx->remote_party_.party_id_);

    Round2BCMessage bc_message;
    bc_message.S_ = ctx->local_party_.S_;
    bc_message.psi_ = ctx->local_party_.psi_;

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


