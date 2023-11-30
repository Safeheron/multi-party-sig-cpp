
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_PARTY_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "crypto-suites/crypto-commitment/kgd_number.h"
#include "multi-party-sig/mpc-flow/mpc-parallel/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/proto_gen/struct.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{

class LocalParty {
public:
    std::string party_id_;
    safeheron::bignum::BN index_;// Share index
    safeheron::bignum::BN x_;
    safeheron::curve::CurvePoint X_;// X = g^x
    safeheron::curve::CurvePoint Y_;
    safeheron::bignum::BN N_; // N = p * q
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN p_;
    safeheron::bignum::BN q_;
    safeheron::bignum::BN alpha_;
    safeheron::bignum::BN beta_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::Party &party) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::Party &party);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class RemoteParty {
public:
    std::string party_id_;
    safeheron::bignum::BN index_; // Share index
    safeheron::curve::CurvePoint X_; // X = g^x
    safeheron::curve::CurvePoint Y_;
    safeheron::bignum::BN N_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::Party &party) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::Party &party);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_PARTY_H
