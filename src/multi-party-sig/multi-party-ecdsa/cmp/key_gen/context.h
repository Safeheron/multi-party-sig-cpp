#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_CONTEXT_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_CONTEXT_H
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/round0.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/round1_6.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_gen/t_party.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_gen {
class Context : public safeheron::mpc_flow::mpc_parallel_v2::MPCContext {
public:
    /**
     * Default constructor
     */
    Context(int total_parties);

    /**
     * A copy constructor
     */
    Context(const Context &ctx);

    /**
     * A copy assignment operator
     */
    Context &operator=(const Context &ctx);

public:
    void BindAllRounds();

    static bool CreateContext(Context &ctx,
                              safeheron::curve::CurveType curve_type,
                              uint32_t threshold, uint32_t n_parties,
                              const safeheron::bignum::BN &index,
                              const std::string &local_party_id,
                              const std::vector <safeheron::bignum::BN> &remote_party_index_arr,
                              const std::vector <std::string> &remote_party_id_arr,
                              const std::string &sid);

    static bool CreateContext(Context &ctx,
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
                              const safeheron::bignum::BN &beta);

    static bool CreateContext(Context &ctx,
                              safeheron::curve::CurveType curve_type,
                              uint32_t threshold, uint32_t n_parties,
                              const safeheron::bignum::BN &x,
                              const safeheron::bignum::BN &index,
                              const std::string &local_party_id,
                              const std::vector <safeheron::bignum::BN> &remote_party_index_arr,
                              const std::vector <std::string> &remote_party_id_arr,
                              const std::string &sid);

    static bool CreateContext(Context &ctx,
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
                              const safeheron::bignum::BN &beta);

public:
    safeheron::multi_party_ecdsa::cmp::minimal_key_gen::Context minimal_key_gen_ctx_;
    safeheron::multi_party_ecdsa::cmp::aux_info_key_refresh::Context aux_info_key_refresh_ctx_;

    safeheron::multi_party_ecdsa::cmp::SignKey sign_key_;

    std::string sid_;

    LocalTParty local_party_;

    Round0 round0_;
    Round1_6 round1_;
    Round1_6 round2_;
    Round1_6 round3_;
    Round1_6 round4_;
    Round1_6 round5_;
    Round1_6 round6_;
};
}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_CONTEXT_H
