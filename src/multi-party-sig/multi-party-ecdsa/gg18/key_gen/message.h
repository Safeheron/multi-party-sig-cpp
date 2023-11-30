
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_MESSAGE_H

#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_gen/proto_gen/key_gen.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_gen {


class Round0BCMessage {
public:
    safeheron::bignum::BN kgc_y_;

    // For range proof
    safeheron::zkp::dln_proof::DLNProof dln_proof_1_;
    safeheron::zkp::dln_proof::DLNProof dln_proof_2_;
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN h1_;
    safeheron::bignum::BN h2_;

    safeheron::bignum::BN index_;
    safeheron::pail::PailPubKey pail_pub_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round0BCMessage &message)const ;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round0BCMessage &message);

    bool ToBase64(std::string &b64)const ;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1BCMessage {
public:
    safeheron::commitment::KgdCurvePoint kgd_y_;
    std::vector<safeheron::curve::CurvePoint> vs_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round1BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round1BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1P2PMessage {
public:
    safeheron::bignum::BN x_ij_;
    safeheron::zkp::no_small_factor_proof::NoSmallFactorProof nsf_proof_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round1P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round1P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round2BCMessage {
public:
    safeheron::curve::CurvePoint pub_;
    safeheron::zkp::dlog::DLogProof dlog_proof_x_;
    safeheron::zkp::pail::PailBlumModulusProof pail_proof_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round2BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_gen::Round2BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};


}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_GEN_MESSAGE_H
