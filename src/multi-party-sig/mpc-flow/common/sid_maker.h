#ifndef SAFEHERON_MPC_FLOW_COMMON_SSID_MAKER_H
#define SAFEHERON_MPC_FLOW_COMMON_SSID_MAKER_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-hash/safe_hash256.h"

namespace safeheron {
namespace mpc_flow {
namespace common {

class SIDMaker{
private:
    safeheron::hash::CSafeHash256 sha;
public:
    static const size_t OUTPUT_SIZE = safeheron::hash::CSafeHash256::OUTPUT_SIZE;

    SIDMaker& Append(const safeheron::bignum::BN &num);
    SIDMaker& Append(const safeheron::curve::CurvePoint &point);
    SIDMaker& Append(const std::string &str);
    SIDMaker& Append(const unsigned char *data, size_t len);

    void Finalize(std::string &ssid);
    SIDMaker& Reset();

};


} // safeheron
} // mpc_flow
} // common

#endif //SAFEHERON_MPC_FLOW_COMMON_SSID_MAKER_H
