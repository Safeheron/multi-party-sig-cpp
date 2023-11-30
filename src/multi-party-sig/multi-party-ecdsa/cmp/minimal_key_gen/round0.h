
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_ROUND0_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_ROUND0_H

#include <string>
#include <vector>
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {


class Round0 : public safeheron::mpc_flow::mpc_parallel_v2::MPCRound {
public:
    Round0() : MPCRound(safeheron::mpc_flow::mpc_parallel_v2::MessageType::None,
                        safeheron::mpc_flow::mpc_parallel_v2::MessageType::BROADCAST) {}

    bool ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) override { return true; }

    bool ReceiveVerify(const std::string &party_id) override { return true; }

    bool ComputeVerify() override;

    bool MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const override;
};

}
}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_ROUND0_H
