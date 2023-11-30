#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/round0.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/context.h"

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_gen {
bool Round0::ComputeVerify() {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    bool ok = ctx->minimal_key_gen_ctx_.PushMessage();
    if (!ok) {
        std::string err_info = safeheron::multi_party_ecdsa::cmp::get_err_info(ctx);
        err_info += make_error_msg(1, __FILE__, __LINE__, __FUNCTION__,
                                   "ctx->minimal_key_gen_ctx_.PushMessage() failed.");
        ctx->PushErrorCode(1, err_info);
        return false;
    }
    return true;
}

bool Round0::MakeMessage(std::vector <std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                         std::vector <std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    ctx->minimal_key_gen_ctx_.PopMessages(out_p2p_msg_arr, out_bc_msg, out_des_arr);

    return true;
}
}
}
}
}