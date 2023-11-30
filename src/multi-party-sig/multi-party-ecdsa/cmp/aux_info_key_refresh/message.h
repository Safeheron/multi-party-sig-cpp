
#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_MESSAGE_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_MESSAGE_H

#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-zkp/zkp.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/aux_info_key_refresh/proto_gen/aux_info_key_refresh.pb.switch.h"

namespace safeheron {
namespace multi_party_ecdsa{
namespace cmp{
namespace aux_info_key_refresh {

class Round0BCMessage {
public:
    std::string ssid_;
    safeheron::bignum::BN index_;
    std::string V_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::aux_info_key_refresh::Round0BCMessage &message)const ;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::aux_info_key_refresh::Round0BCMessage &message);

    bool ToBase64(std::string &b64)const ;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round1BCMessage {
public:
    std::string ssid_;
    safeheron::bignum::BN index_;
    std::map<std::string, safeheron::curve::CurvePoint> map_party_id_X_;
    std::vector<safeheron::curve::CurvePoint> c_;
    std::map<std::string, safeheron::curve::CurvePoint> map_party_id_A_;
    safeheron::curve::CurvePoint Y_;
    safeheron::curve::CurvePoint B_;
    safeheron::bignum::BN N_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    safeheron::zkp::dln_proof::TwoDLNProof psi_tilde_;
    std::string rho_;
    std::string u_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::aux_info_key_refresh::Round1BCMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::aux_info_key_refresh::Round1BCMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};

class Round2P2PMessage {
public:
    std::string ssid_;
    safeheron::bignum::BN index_;
    safeheron::zkp::pail::PailBlumModulusProof psi_;
    safeheron::zkp::no_small_factor_proof::NoSmallFactorProof phi_ij_;
    safeheron::zkp::dlog::DLogProof_V2 pi_;
    safeheron::bignum::BN C_;
    safeheron::zkp::dlog::DLogProof_V2 psi_ij_;

public:
    bool ToProtoObject(safeheron::proto::multi_party_ecdsa::cmp::aux_info_key_refresh::Round2P2PMessage &message) const;

    bool FromProtoObject(const safeheron::proto::multi_party_ecdsa::cmp::aux_info_key_refresh::Round2P2PMessage &message);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str)const ;

    bool FromJsonString(const std::string &json_str);
};


}
}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_AUX_INFO_KEY_REFRESH_MESSAGE_H
