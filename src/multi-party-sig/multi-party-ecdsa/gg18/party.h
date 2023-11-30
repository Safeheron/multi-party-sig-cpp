
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_PARTY_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/proto_gen/struct.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{

class LocalParty {
public:
    std::string party_id_;
    // Share index
    safeheron::bignum::BN index_;
    // Private key for pailliar cryptosystem
    safeheron::pail::PailPrivKey pail_priv_;
    // Public key for pailliar cryptosystem
    safeheron::pail::PailPubKey pail_pub_;
    // Original secret share
    safeheron::bignum::BN x_;
    // y = g^u
    safeheron::curve::CurvePoint g_x_;

    // For range proof
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN h1_;
    safeheron::bignum::BN h2_;
    safeheron::bignum::BN p_;
    safeheron::bignum::BN q_;
    safeheron::bignum::BN alpha_;
    safeheron::bignum::BN beta_;
public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::Party &party) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::Party &party);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class RemoteParty {
public:
    std::string party_id_;
    // Share index
    safeheron::bignum::BN index_;
    // Public key for pailliar cryptosystem
    safeheron::pail::PailPubKey pail_pub_;
    // y = g^u
    safeheron::curve::CurvePoint g_x_;

    // For range proof
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN h1_;
    safeheron::bignum::BN h2_;
public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::Party &party) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::Party &party);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

}
}
}


#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_PARTY_H
