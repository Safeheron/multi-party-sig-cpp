#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/context.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_gen {
Context::Context(int total_parties) : MPCContext(total_parties), minimal_key_gen_ctx_(total_parties),
                                      aux_info_key_refresh_ctx_(total_parties) {
    BindAllRounds();
}

Context::Context(const Context &ctx) : MPCContext(ctx), minimal_key_gen_ctx_(ctx.minimal_key_gen_ctx_),
                                       aux_info_key_refresh_ctx_(ctx.aux_info_key_refresh_ctx_) {
    // Assign the member variables.
    sid_ = ctx.sid_;

    sign_key_ = ctx.sign_key_;

    local_party_ = ctx.local_party_;

    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    round4_ = ctx.round4_;
    round5_ = ctx.round5_;
    round6_ = ctx.round6_;
    // End Assignments.

    BindAllRounds();
}

Context &Context::operator=(const Context &ctx) {
    if (this == &ctx) {
        return *this;
    }

    MPCContext::operator=(ctx);

    // Assign all the member variables.
    minimal_key_gen_ctx_ = ctx.minimal_key_gen_ctx_;
    aux_info_key_refresh_ctx_ = ctx.aux_info_key_refresh_ctx_;

    sid_ = ctx.sid_;

    sign_key_ = ctx.sign_key_;

    local_party_ = ctx.local_party_;

    round0_ = ctx.round0_;
    round1_ = ctx.round1_;
    round2_ = ctx.round2_;
    round3_ = ctx.round3_;
    round4_ = ctx.round4_;
    round5_ = ctx.round5_;
    round6_ = ctx.round6_;
    // End Assignments.

    BindAllRounds();

    return *this;
}

bool Context::CreateContext(Context &ctx,
                            safeheron::curve::CurveType curve_type,
                            uint32_t threshold, uint32_t n_parties,
                            const safeheron::bignum::BN &index,
                            const std::string &local_party_id,
                            const std::vector <safeheron::bignum::BN> &remote_party_index_arr,
                            const std::vector <std::string> &remote_party_id_arr,
                            const std::string &sid) {
    bool ok = safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context::CreateContext(ctx.minimal_key_gen_ctx_,
                                                                                         curve_type,
                                                                                         threshold,
                                                                                         n_parties,
                                                                                         index,
                                                                                         local_party_id,
                                                                                         remote_party_index_arr,
                                                                                         remote_party_id_arr,
                                                                                         sid);
    if (!ok) return false;

    ctx.sid_ = sid;

    ctx.local_party_.prepared_ = false;

    return true;
}

bool Context::CreateContext(Context &ctx,
                            safeheron::curve::CurveType curve_type,
                            uint32_t threshold, uint32_t n_parties,
                            const safeheron::bignum::BN &index,
                            const std::string &local_party_id,
                            const std::vector <safeheron::bignum::BN> &remote_party_index_arr,
                            const std::vector <std::string> &remote_party_id_arr,
                            const std::string &sid,
                            const safeheron::bignum::BN &N,
                            const safeheron::bignum::BN &s,
                            const safeheron::bignum::BN &t,
                            const safeheron::bignum::BN &p,
                            const safeheron::bignum::BN &q,
                            const safeheron::bignum::BN &alpha,
                            const safeheron::bignum::BN &beta) {
    bool ok = safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context::CreateContext(ctx.minimal_key_gen_ctx_,
                                                                                         curve_type,
                                                                                         threshold,
                                                                                         n_parties,
                                                                                         index,
                                                                                         local_party_id,
                                                                                         remote_party_index_arr,
                                                                                         remote_party_id_arr,
                                                                                         sid);
    if (!ok) return false;

    ctx.local_party_.prepared_ = true;
    ctx.local_party_.N_ = N;
    ctx.local_party_.s_ = s;
    ctx.local_party_.t_ = t;
    ctx.local_party_.p_ = p;
    ctx.local_party_.q_ = q;
    ctx.local_party_.alpha_ = alpha;
    ctx.local_party_.beta_ = beta;

    ctx.sid_ = sid;

    return true;
}

bool Context::CreateContext(Context &ctx,
                            safeheron::curve::CurveType curve_type,
                            uint32_t threshold, uint32_t n_parties,
                            const safeheron::bignum::BN &x,
                            const safeheron::bignum::BN &index,
                            const std::string &local_party_id,
                            const std::vector <safeheron::bignum::BN> &remote_party_index_arr,
                            const std::vector <std::string> &remote_party_id_arr,
                            const std::string &sid) {
    bool ok = safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context::CreateContext(ctx.minimal_key_gen_ctx_,
                                                                                         curve_type,
                                                                                         threshold,
                                                                                         n_parties,
                                                                                         x,
                                                                                         index,
                                                                                         local_party_id,
                                                                                         remote_party_index_arr,
                                                                                         remote_party_id_arr,
                                                                                         sid);
    if (!ok) return false;

    ctx.sid_ = sid;

    ctx.local_party_.prepared_ = false;

    return true;
}

bool Context::CreateContext(Context &ctx,
                            safeheron::curve::CurveType curve_type,
                            uint32_t threshold, uint32_t n_parties,
                            const safeheron::bignum::BN &x,
                            const safeheron::bignum::BN &index,
                            const std::string &local_party_id,
                            const std::vector <safeheron::bignum::BN> &remote_party_index_arr,
                            const std::vector <std::string> &remote_party_id_arr,
                            const std::string &sid,
                            const safeheron::bignum::BN &N,
                            const safeheron::bignum::BN &s,
                            const safeheron::bignum::BN &t,
                            const safeheron::bignum::BN &p,
                            const safeheron::bignum::BN &q,
                            const safeheron::bignum::BN &alpha,
                            const safeheron::bignum::BN &beta) {
    bool ok = safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context::CreateContext(ctx.minimal_key_gen_ctx_,
                                                                                         curve_type,
                                                                                         threshold,
                                                                                         n_parties,
                                                                                         x,
                                                                                         index,
                                                                                         local_party_id,
                                                                                         remote_party_index_arr,
                                                                                         remote_party_id_arr,
                                                                                         sid);
    if (!ok) return false;

    ctx.local_party_.prepared_ = true;
    ctx.local_party_.N_ = N;
    ctx.local_party_.s_ = s;
    ctx.local_party_.t_ = t;
    ctx.local_party_.p_ = p;
    ctx.local_party_.q_ = q;
    ctx.local_party_.alpha_ = alpha;
    ctx.local_party_.beta_ = beta;

    ctx.sid_ = sid;

    return true;
}

void Context::BindAllRounds() {
    RemoveAllRounds();
    AddRound(&round0_);
    AddRound(&round1_);
    AddRound(&round2_);
    AddRound(&round3_);
    AddRound(&round4_);
    AddRound(&round5_);
    AddRound(&round6_);
}

}
}
}
}