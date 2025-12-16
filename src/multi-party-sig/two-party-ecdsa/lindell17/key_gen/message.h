#ifndef MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_KEY_GEN_MESSAGE_H
#define MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_KEY_GEN_MESSAGE_H
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/dlog_proof_v2.h"
#include "crypto-suites/crypto-zkp/pdl/pdl_proof.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-zkp/pail/pail_n_proof.h"
#include "crypto-suites/crypto-zkp/pail/pail_enc_range_proof_v3.h"
#include "proto_gen/key_gen.pb.switch.h"


namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
namespace key_gen {

class P1Message1 {
public:
    std::string commitment_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message1 &p1_msg1) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message1 &p1_msg1);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P2Message1 {
public:
    safeheron::curve::CurvePoint Q2_;
    safeheron::zkp::dlog::DLogProof_V2 d_log_proof_Q2_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P2Message1 &p2_msg1) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P2Message1 &p2_msg1);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P1Message2 {
public:
    safeheron::curve::CurvePoint Q1_;
    safeheron::zkp::dlog::DLogProof_V2 d_log_proof_Q1_;
    std::string blind_factor_;
    safeheron::bignum::BN c_;
    safeheron::pail::PailPubKey pail_pub_;
    safeheron::zkp::pail::PailNProof pail_n_proof_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message2 &p1_msg2) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message2 &p1_msg2);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P2Message2 {
public:
    safeheron::zkp::pdl::PDLVMessage1 pdl_v_message1_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P2Message2 &p2_msg2) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P2Message2 &p2_msg2);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P1Message3 {
public:
    safeheron::zkp::pdl::PDLPMessage1 pdl_p_message1_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message3 &p1_msg3) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message3 &p1_msg3);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P2Message3 {
public:
    safeheron::zkp::pdl::PDLVMessage2 pdl_v_message2_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P2Message3 &p2_msg3) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P2Message3 &p2_msg3);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

class P1Message4 {
public:
    safeheron::zkp::pdl::PDLPMessage2 pdl_p_message2_;
public:
    bool ToProtoObject(safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message4 &p1_msg4) const;

    bool FromProtoObject(const safeheron::proto::two_party_ecdsa::lindell17::key_gen::P1Message4 &p1_msg4);

    bool ToBase64(std::string &b64) const;

    bool FromBase64(const std::string &b64);

    bool ToJsonString(std::string &json_str) const;

    bool FromJsonString(const std::string &json_str);
};

}
}
}
}

#endif //MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_KEY_GEN_MESSAGE_H
