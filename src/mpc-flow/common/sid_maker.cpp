//
// Created by Sword03 on 2023/9/11.
//

#include "sid_maker.h"

namespace safeheron {
namespace mpc_flow {
namespace common {

SIDMaker& SIDMaker::Append(const safeheron::bignum::BN &num){
    std::string buf;
    num.ToBytesBE(buf);
    sha.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    return *this;
}

SIDMaker& SIDMaker::Append(const safeheron::curve::CurvePoint &point){
    std::string buf;
    point.x().ToBytesBE(buf);
    sha.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    point.y().ToBytesBE(buf);
    sha.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    return *this;
}

SIDMaker& SIDMaker::Append(const std::string &str){
    sha.Write(reinterpret_cast<const unsigned char *>(str.c_str()), str.size());
    return *this;
}

SIDMaker& SIDMaker::Append(const unsigned char *data, size_t len){
    sha.Write(data, len);
    return *this;
}

void SIDMaker::Finalize(std::string &ssid){
    unsigned char t_com[OUTPUT_SIZE];
    sha.Finalize(t_com);
    ssid.assign((const char *)t_com, OUTPUT_SIZE);
}

SIDMaker& SIDMaker::Reset() {
    sha.Reset();
    return *this;
}

} // safeheron
} // mpc_flow
} // common
