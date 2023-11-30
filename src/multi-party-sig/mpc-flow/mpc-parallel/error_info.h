#ifndef SAFEHERON_MPC_FLOW_ERROR_INFO_H
#define SAFEHERON_MPC_FLOW_ERROR_INFO_H

#include <string>

namespace safeheron{
namespace mpc_flow{
namespace mpc_parallel{


struct ErrorInfo {
public:
    int code_;
    std::string info_;

    ErrorInfo() { code_ = 0; }
};

}
}
}

#endif //SAFEHERON_MPC_FLOW_ERROR_INFO_H
