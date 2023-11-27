#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_CONTEXT_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_CONTEXT_H
#include "mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "crypto-curve/curve.h"
#include "crypto-bn/bn.h"
#include "t_party.h"
#include "round0.h"
#include "round1.h"
#include "round2.h"
#include "round3.h"

/**
 * Key recovery protocol for threshold 2-3.
 */

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {

class Context : public safeheron::mpc_flow::mpc_parallel_v2::MPCContext {
public:
    /**
     * Default constructor
     * @param total_parties
     */
    Context(int total_parties);
    /**
     * Copy constructor
     * @param ctx
     */
    Context(const Context &ctx);
    /**
     * Copy assignment operator
     * @param ctx
     * @return
     */
    Context &operator=(const Context &ctx);
public:
    void BindAllRounds();
     /**
      * Fill up ctx.
      * @param ctx
      * @param curve_type
      * @param x local secret key shard
      * @param i local party index
      * @param j remote party index (no lost key)
      * @param k the third party index (lost key)
      * @param local_party_id
      * @param remote_party_id
      * @return
      */
    static bool CreateContext(Context &ctx,
                              safeheron::curve::CurveType curve_type,
                              const safeheron::bignum::BN &x,
                              const safeheron::bignum::BN &i,
                              const safeheron::bignum::BN &j,
                              const safeheron::bignum::BN &k,
                              const std::string &local_party_id,
                              const std::string &remote_party_id);
public:
    safeheron::curve::CurveType curve_type_;

    //local secret key shard
    safeheron::bignum::BN x_;

    //partial secret key shard of the third party
    safeheron::bignum::BN s_;

    //public key shard of the third party
    safeheron::curve::CurvePoint X_k_;

    //full public key
    safeheron::curve::CurvePoint pub_;

    LocalTParty local_party_;
    RemoteTParty remote_party_;

    Round0 round0_;
    Round1 round1_;
    Round2 round2_;
    Round3 round3_;
};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_CONTEXT_H
