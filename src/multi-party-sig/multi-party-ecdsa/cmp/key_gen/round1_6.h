#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_ROUND0_6_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_ROUND0_6_H
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_round.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp{
namespace key_gen {
class Round1_6 : public safeheron::mpc_flow::mpc_parallel_v2::MPCRound {
public:
    Round1_6() : MPCRound(safeheron::mpc_flow::mpc_parallel_v2::MessageType::None,
                          safeheron::mpc_flow::mpc_parallel_v2::MessageType::None) {}

    bool ParseMsg(const std::string &p2p_msg, const std::string &bc_msg,
                  const std::string &party_id) override;

    bool ReceiveVerify(const std::string &party_id) override { return true; }

    bool ComputeVerify() override { return true; }

    bool MakeMessage(std::vector <std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                     std::vector <std::string> &out_des_arr) const override;
};
}
}
}
}
#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_ROUND0_6_H
