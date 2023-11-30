
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ROUND3_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ROUND3_H

#include <string>
#include <vector>
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/message.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/identification.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {


class Round3 : public safeheron::mpc_flow::mpc_parallel_v2::MPCRound {
public:
    std::vector<Round2P2PMessage> p2p_message_arr_;

    Round3() : MPCRound(safeheron::mpc_flow::mpc_parallel_v2::MessageType::P2P,
                        safeheron::mpc_flow::mpc_parallel_v2::MessageType::P2P) {}

    void Init() override;

    bool ParseMsg(const std::string &p2p_msg, const std::string &bc_msg, const std::string &party_id) override;

    bool ReceiveVerify(const std::string &party_id) override;

    bool ComputeVerify() override;

    bool MakeMessage(std::vector<std::string> &out_p2p_msg_arr, std::string &out_bc_msg,
                             std::vector<std::string> &out_des_arr) const override;

    bool BuildProof();
    bool VerifyProof(std::map<std::string, ProofInPreSignPhase> &map_proof,
                     std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_D,
                     std::map<std::string, std::map<std::string, safeheron::bignum::BN>> &all_F);
};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_ROUND3_H
