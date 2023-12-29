#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-hash/safe_hash256.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/round0.h"

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

    //- Sample a_{i} \in Z_q
    //- Compute A_{i} = g^{a_{i}}
    ctx->local_party_.a_i_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.A_i_ = curv->g * ctx->local_party_.a_i_;

    //- Sample r_i \in Z_q
    //- Compute R_i = g^{r_i}
    ctx->local_party_.r_i_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.R_i_ = curv->g * ctx->local_party_.r_i_;

    //- Sample t_i \in Z_q
    //- Compute T_i = g^{t_i}
    ctx->local_party_.t_i_ = safeheron::rand::RandomBNLt(curv->n);
    ctx->local_party_.T_i_ = curv->g * ctx->local_party_.t_i_;

    // Compute \phi_i = \mathcal{M}(prove, \Pi^{log}, (X_i); (x_i, r_i))
    ctx->local_party_.phi_i_.ProveWithREx(ctx->x_i_, ctx->local_party_.r_i_, ctx->curve_type_);

    // Compute V_i = H(X_i, i, j, k, A_i, B_i, R_i, T_i , \phi_{i})
    safeheron::hash::CSafeHash256 sha256;
    uint8_t digest[safeheron::hash::CSafeHash256::OUTPUT_SIZE];

    std::string buf;
    ctx->local_party_.X_i_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.i_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.j_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    ctx->local_party_.k_.ToBytesBE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.A_i_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.R_i_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.T_i_.EncodeFull(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    ctx->local_party_.phi_i_.ToBase64(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());

    sha256.Finalize(digest);
    ctx->local_party_.V_i_.assign((const char*)digest, sizeof(digest));

    return true;
}

bool Round0::MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector<std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    out_p2p_msg_arr.clear();
    out_bc_msg.clear();
    out_des_arr.clear();

    out_des_arr.push_back(ctx->remote_party_.party_id_);

    std::string base64;
    Round0P2PMessage p2p_message;
    p2p_message.V_ = ctx->local_party_.V_i_;
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

