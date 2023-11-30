
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_MESSAGE_H

#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/key_refresh/proto_gen/key_refresh.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace gg18{
namespace key_refresh {


class Round0BCMessage {
public:
    std::string V_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round0BCMessage &message)const ;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round0BCMessage &message);

    bool ToBase64(std::string &b64)const ;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1BCMessage {
public:
    std::vector<safeheron::curve::CurvePoint> vs_;
    safeheron::zkp::dln_proof::DLNProof dln_proof_1_;
    safeheron::zkp::dln_proof::DLNProof dln_proof_2_;
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN h1_;
    safeheron::bignum::BN h2_;
    safeheron::pail::PailPubKey pail_pub_;
    std::string blind_factor_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round1BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round1BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1P2PMessage {
public:
    safeheron::bignum::BN x_ij_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round1P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round1P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round2P2PMessage {
public:
    safeheron::zkp::dlog::DLogProof dlog_proof_x_;
    safeheron::zkp::pail::PailBlumModulusProof pail_proof_;
    safeheron::zkp::no_small_factor_proof::NoSmallFactorProof nsf_proof_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round2P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round2P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round3BCMessage {
public:
    int ack_status_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round3BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::gg18::key_refresh::Round3BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_KEY_REFRESH_MESSAGE_H
