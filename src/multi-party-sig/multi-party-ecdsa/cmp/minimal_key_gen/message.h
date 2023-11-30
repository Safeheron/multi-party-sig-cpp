
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_MESSAGE_H

#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_key_gen/proto_gen/minimal_key_gen.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace minimal_key_gen {

class Round0BCMessage {
public:
    std::string sid_;
    safeheron::bignum::BN index_;
    std::string V_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round0BCMessage &message)const ;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round0BCMessage &message);

    bool ToBase64(std::string &b64)const ;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1BCMessage {
public:
    std::string sid_;
    safeheron::bignum::BN index_;
    std::string rid_;
    safeheron::curve::CurvePoint X_;
    safeheron::curve::CurvePoint A_;
    safeheron::curve::CurvePoint B_;
    std::map<std::string, safeheron::curve::CurvePoint> map_party_id_X_;
    std::vector<safeheron::curve::CurvePoint> c_;
    std::string u_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round1BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round1BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1P2PMessage {
public:
    std::string sid_;
    safeheron::bignum::BN index_;
    safeheron::bignum::BN x_ij_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round1P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round1P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round2BCMessage {
public:
    std::string sid_;
    safeheron::bignum::BN index_;
    safeheron::zkp::dlog::DLogProof_V2 psi_;
    safeheron::zkp::dlog::DLogProof_V2 phi_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round2BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::minimal_key_gen::Round2BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};


}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_NAKED_KEY_GEN_MESSAGE_H
