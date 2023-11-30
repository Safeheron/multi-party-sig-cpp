
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_MESSAGE_H

#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign/proto_gen/sign.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace sign {

class Round0BCMessage {
public:
    std::string ssid_;
    safeheron::bignum::BN index_;
    safeheron::bignum::BN K_;
    safeheron::bignum::BN G_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::Round0BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::Round0BCMessage &message);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round0P2PMessage {
public:
    std::string ssid_;
    safeheron::bignum::BN index_;
    zkp::pail::PailEncRangeProof_V2 psi_0_ij_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::Round0P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::Round0P2PMessage &message);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1P2PMessage {
public:
    std::string ssid_;
    safeheron::bignum::BN index_;

    safeheron::curve::CurvePoint Gamma_;
    safeheron::bignum::BN D_ij_;
    safeheron::bignum::BN F_ij_;
    safeheron::bignum::BN D_hat_ij_;
    safeheron::bignum::BN F_hat_ij_;

    zkp::pail::PailAffGroupEleRangeProof_V2 psi_ij_;
    zkp::pail::PailAffGroupEleRangeProof_V2 psi_hat_ij_;
    zkp::pail::PailEncGroupEleRangeProof psi_prime_ij_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::Round1P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::Round1P2PMessage &message);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round2P2PMessage {
public:
    std::string ssid_;
    safeheron::bignum::BN index_;
    safeheron::bignum::BN delta_;
    safeheron::curve::CurvePoint Delta_;
    safeheron::zkp::pail::PailEncGroupEleRangeProof psi_double_prime_ij_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::Round2P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::Round2P2PMessage &message);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round3P2PMessage {
public:
    std::string ssid_;
    safeheron::bignum::BN index_;
    safeheron::bignum::BN sigma_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::sign::Round3P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::sign::Round3P2PMessage &message);

    bool ToBase64(std::string &base64) const;

    bool FromBase64(const std::string &base64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_MESSAGE_H
