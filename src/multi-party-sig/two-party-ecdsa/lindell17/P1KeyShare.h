#ifndef MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_P1KEYSHARE_H
#define MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_P1KEYSHARE_H
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve_point.h"
#include "proto_gen/struct.pb.switch.h"

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
class P1KeyShare {
public:
    safeheron::bignum::BN x1_;
    safeheron::curve::CurvePoint Q_;
    safeheron::pail::PailPrivKey pail_priv_;
    safeheron::pail::PailPubKey pail_pub_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::P1KeyShare &p1_key_share) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::P1KeyShare &p1_key_share);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};
}
}
}



#endif //MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_P1KEYSHARE_H
