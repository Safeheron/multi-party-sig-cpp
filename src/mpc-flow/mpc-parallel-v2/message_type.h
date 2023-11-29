//
// Created by Sword03 on 2023/2/27.
//

#ifndef SAFEHERON_MPC_FLOW_MPC_PARALLEL_V2_MESSAGE_TYPE_H
#define SAFEHERON_MPC_FLOW_MPC_PARALLEL_V2_MESSAGE_TYPE_H

#include <string>

namespace safeheron {
namespace mpc_flow {
namespace mpc_parallel_v2 {

enum MessageType : std::uint8_t {
    None = 0,
    P2P = 1,
    BROADCAST = 2,
    P2P_BROADCAST = 3,
};

}
}
}


#endif //SAFEHERON_MPC_FLOW_MPC_PARALLEL_V2_MESSAGE_TYPE_H
