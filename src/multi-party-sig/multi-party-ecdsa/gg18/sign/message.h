
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_ONCE_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_ONCE_MESSAGE_H

#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign/proto_gen/sign.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace sign{

class Round0BCMessage {
public:
    safeheron::bignum::BN commitment_;
    safeheron::bignum::BN message_a_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round0BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round0BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round0P2PMessage {
public:
    safeheron::zkp::pail::PailEncRangeProof_V1 alice_proof_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round0P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round0P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1P2PMessage {
public:
    safeheron::bignum::BN message_b_for_k_gamma_;
    safeheron::bignum::BN message_b_for_k_w_;
    zkp::pail::PailAffRangeProof bob_proof_1_;
    zkp::pail::PailAffGroupEleRangeProof_V1 bob_proof_2_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round1P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round1P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round2BCMessage {
public:
    safeheron::bignum::BN delta_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round2BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round2BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round3BCMessage {
public:
    safeheron::bignum::BN blind_factor_;
    zkp::dlog::DLogProof dlog_proof_gamma_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round3BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round3BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round4BCMessage {
public:
    safeheron::bignum::BN commitment_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round4BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round4BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round5BCMessage {
public:
    curve::CurvePoint V_;
    curve::CurvePoint A_;
    safeheron::bignum::BN blind_factor_;
    zkp::linear_combination::LinearCombinationProof lc_proof_VRG_;
    zkp::dlog::DLogProof_V2 dlog_proof_rho_;
public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round5BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round5BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round6BCMessage {
public:
    safeheron::bignum::BN commitment_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round6BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round6BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round7BCMessage {
public:
    curve::CurvePoint U_;
    curve::CurvePoint T_;
    safeheron::bignum::BN blind_factor_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round7BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round7BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round8BCMessage {
public:
    safeheron::bignum::BN si_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::sign::Round8BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::sign::Round8BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_ONCE_MESSAGE_H
