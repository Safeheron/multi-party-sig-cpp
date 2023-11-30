#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/round1_6.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/context.h"

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_gen {
bool Round1_6::ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());

    bool ok = true;
    std::string err_info;
    if (ctx->get_cur_round() < ctx->minimal_key_gen_ctx_.get_total_rounds()) {
        ok = ctx->minimal_key_gen_ctx_.PushMessage(p2p_msg, bc_msg, party_id, ctx->get_cur_round() - 1);
        if (!ok) {
            err_info = safeheron::multi_party_ecdsa::cmp::get_err_info(ctx);
            err_info += make_error_msg(1, __FILE__, __LINE__, __FUNCTION__,
                                       "ctx->minimal_key_gen_ctx_.PushMessage(p2p_msg, bc_msg, party_id, ctx->get_cur_round() - 1) failed.");
            ctx->PushErrorCode(1, err_info);
            return false;
        }

        if (ctx->get_cur_round() == ctx->minimal_key_gen_ctx_.get_total_rounds() - 1 && ctx->minimal_key_gen_ctx_.IsCurRoundFinished()) {
            if (ctx->local_party_.prepared_) {
                ok = safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context::CreateContext(
                        ctx->aux_info_key_refresh_ctx_,
                        ctx->minimal_key_gen_ctx_.minimal_sign_key_,
                        ctx->sid_,
                        ctx->local_party_.N_,
                        ctx->local_party_.s_,
                        ctx->local_party_.t_,
                        ctx->local_party_.p_,
                        ctx->local_party_.q_,
                        ctx->local_party_.alpha_,
                        ctx->local_party_.beta_);
            } else {
                ok = safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context::CreateContext(
                        ctx->aux_info_key_refresh_ctx_,
                        ctx->minimal_key_gen_ctx_.minimal_sign_key_,
                        ctx->sid_);
            }
            if (!ok) {
                ctx->PushErrorCode(1, __FILE__, __LINE__, __FUNCTION__, "Failed to create key refresh Context.");
                return false;
            }
            ok = ctx->aux_info_key_refresh_ctx_.PushMessage();
            if (!ok) {
                err_info = safeheron::multi_party_ecdsa::cmp::get_err_info(ctx);
                err_info += make_error_msg(1, __FILE__, __LINE__, __FUNCTION__,
                                           "ctx->aux_info_key_refresh_ctx_.PushMessage() failed.");
                ctx->PushErrorCode(1, err_info);
                return false;
            }
        }
    } else {
        ok = ctx->aux_info_key_refresh_ctx_.PushMessage(p2p_msg, bc_msg, party_id, ctx->get_cur_round() -
                                                                                   ctx->minimal_key_gen_ctx_.get_total_rounds());
        if (!ok) {
            err_info = safeheron::multi_party_ecdsa::cmp::get_err_info(ctx);
            err_info += make_error_msg(1, __FILE__, __LINE__, __FUNCTION__,
                                       "ctx->aux_info_key_refresh_ctx_.PushMessage(p2p_msg, bc_msg, party_id, ctx->get_cur_round() - ctx->minimal_key_gen_ctx_.get_total_rounds()) failed.");
            ctx->PushErrorCode(1, err_info);
            return false;
        }
    }

    return true;
}

bool Round1_6::MakeMessage(std::vector <std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                           std::vector <std::string> &out_des_arr) const {
    Context *ctx = dynamic_cast<Context *>(this->get_mpc_context());
    if (ctx->get_cur_round() < ctx->minimal_key_gen_ctx_.get_total_rounds() - 1) {
        ctx->minimal_key_gen_ctx_.PopMessages(out_p2p_msg_arr, out_bc_msg, out_des_arr);
    } else if (ctx->get_cur_round() < ctx->get_total_rounds() - 1) {
        ctx->aux_info_key_refresh_ctx_.PopMessages(out_p2p_msg_arr, out_bc_msg, out_des_arr);
    } else {
        ctx->sign_key_ = ctx->aux_info_key_refresh_ctx_.sign_key_;
    }

    return true;
}

}
}
}
}