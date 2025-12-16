#ifndef MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_MESSAGE_H
#define MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_MESSAGE_H
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/dlog_proof_v2.h"
#include "proto_gen/sign.pb.switch.h"

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
namespace sign {

class P1Message0 {
public:
    std::string sid1_commitment_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::sign::P1Message0 &p1_msg0) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::sign::P1Message0 &p1_msg0);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P2Message0 {
public:
    std::string sid2_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message0 &p2_msg0) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message0 &p2_msg0);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P1Message1 {
public:
    std::string sid1_;
    std::string sid1_blind_factor_;
    std::string zk_pk_commitment_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::sign::P1Message1 &p1_msg1) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::sign::P1Message1 &p1_msg1);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P2Message1 {
public:
    safeheron::curve::CurvePoint R2_;
    safeheron::zkp::dlog::DLogProof_V2 d_log_proof_R2_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message1 &p2_msg1) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message1 &p2_msg1);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P1Message2 {
public:
    safeheron::curve::CurvePoint R1_;
    safeheron::zkp::dlog::DLogProof_V2 d_log_proof_R1_;
    safeheron::bignum::BN t_;
    std::string zk_pk_blind_factor_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::sign::P1Message2 &p1_msg2) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::sign::P1Message2 &p1_msg2);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P2Message2 {
public:
    safeheron::bignum::BN c3_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message2 &p2_msg2) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::sign::P2Message2 &p2_msg2);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);

};

}
}
}
}

#endif //MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_MESSAGE_H
