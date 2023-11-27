#include "round0.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "crypto-curve/curve.h"
#include "crypto-hash/sha256.h"

#include "context.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {

bool Round0::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(ctx->curve_type_);
    if (!curv) {
        ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "ctx->curve_type_ is invalid!");
        return false;
    }

    ctx->local_party_.a_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.A_ = curv->g * ctx->local_party_.a_;

    ctx->local_party_.b_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.B_ = curv->g * ctx->local_party_.b_;

    ctx->local_party_.r_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.R_ = curv->g * ctx->local_party_.r_;

    ctx->local_party_.t_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.T_ = curv->g * ctx->local_party_.t_;

    ctx->local_party_.phi_.ProveWithREx(ctx->x_, ctx->local_party_.r_, ctx->curve_type_);

    safeheron::hash::CSHA256 sha256;
    uint8_t digest[safeheron::hash::CSHA256::OUTPUT_SIZE];

    std::string buf;
    ctx->local_party_.X_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.X_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.i_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.j_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.k_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.A_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.A_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.B_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.B_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.R_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.R_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.T_.x().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.T_.y().ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.phi_.ToBase64(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    sha256.Finalize(digest);
    ctx->local_party_.V_.assign((const char*)digest, sizeof(digest));

    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    out_des_arr.push_back(ctx->remote_party_.party_id_);

    Round0BCMessage bc_message;
    bc_message.V_ = ctx->local_party_.V_;
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

