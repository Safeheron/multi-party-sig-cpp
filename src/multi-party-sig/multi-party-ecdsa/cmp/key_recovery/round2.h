#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_ROUND2_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_ROUND2_H
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/key_recovery/message.h"

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {
class Round2 : public safeheron::mpc_flow::mpc_parallel_v2::MPCRound {
public:
    Round1P2PMessage p2p_message_;

    Round2() : MPCRound(safeheron::mpc_flow::mpc_parallel_v2::MessageType::P2P,
                        safeheron::mpc_flow::mpc_parallel_v2::MessageType::P2P) {}

    bool ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) override;

    bool ReceiveVerify(const std::string &party_id) override;

    bool ComputeVerify() override;

    bool MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg, std::vector<std::string> &out_des_arr) const override;
};
}
}
}
}
#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_ROUND2_H
