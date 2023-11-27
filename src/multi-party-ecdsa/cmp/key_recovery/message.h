#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_MESSAGE_H
#include <string>
#include "crypto-curve/curve_point.h"
#include "crypto-zkp/dlog_proof_v2.h"
#include "proto_gen/key_recovery.pb.switch.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_recovery {
class Round0BCMessage {
public:
    std::string V_;
public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round0BCMessage &message) const ;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round0BCMessage &message);

    bool ToBase64(std::string &b64) const ;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1BCMessage {
public:
    safeheron::curve::CurvePoint X_;
    safeheron::bignum::BN i_;
    safeheron::bignum::BN j_;
    safeheron::bignum::BN k_;
    safeheron::curve::CurvePoint A_;
    safeheron::curve::CurvePoint B_;
    safeheron::curve::CurvePoint R_;
    safeheron::curve::CurvePoint T_;
    safeheron::zkp::dlog::DLogProof_V2 phi_;
public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round1BCMessage &message) const ;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round1BCMessage &message);

    bool ToBase64(std::string &b64) const ;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const ;

    bool FromJsonString(const std::string &json_str);
};

class Round2BCMessage {
public:
    safeheron::curve::CurvePoint S_;
    safeheron::zkp::dlog::DLogProof_V2 psi_;
public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round2BCMessage &message) const ;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::key_recovery::Round2BCMessage &message);

    bool ToBase64(std::string &b64) const ;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const ;

    bool FromJsonString(const std::string &json_str);
};

}
}
}
}
#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_RECOVERY_MESSAGE_H
