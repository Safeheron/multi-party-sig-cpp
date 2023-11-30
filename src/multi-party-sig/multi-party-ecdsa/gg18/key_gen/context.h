
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_CONTEXT_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_CONTEXT_H

#include <vector>
#include "crypto-suites/crypto-bn/bn.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/party.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/t_party.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/round0.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/round1.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/round2.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/round3.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/util.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
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
                              const std::string &workspace_id,
                              uint32_t threshold,
                              uint32_t n_parties,
                              const std::string &party_id,
                              const safeheron::bignum::BN &index,
                              const std::vector<std::string> &remote_party_id_arr);

public:
    safeheron::curve::CurveType curve_type_;
    SignKey sign_key_;
    LocalTParty local_party_;
    std::vector<RemoteTParty> remote_parties_;
    Round0 round0_;
    Round1 round1_;
    Round2 round2_;
    Round3 round3_;

    safeheron::curve::CurvePoint X_;
};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_CONTEXT_H
