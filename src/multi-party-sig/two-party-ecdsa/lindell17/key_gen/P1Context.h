#ifndef MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_KEY_GEN_P1CONTEXT_H
#define MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_KEY_GEN_P1CONTEXT_H
#include "multi-party-sig/two-party-ecdsa//lindell17/P1KeyShare.h"
#include "crypto-suites/crypto-zkp/dlog_proof_v2.h"
#include "crypto-suites/crypto-zkp/pdl/pdl_proof.h"

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
namespace key_gen {

class P1Context {
public:
    P1Context() : c_type_(safeheron::curve::CurveType::INVALID_CURVE) {}

    bool CreateContext(const safeheron::curve::CurveType &c_type);

    bool CreateContext(const safeheron::curve::CurveType &c_type, const safeheron::bignum::BN &x1);

public:
    bool Step1(std::string &out_msg);

    bool Step2(const std::string &in_msg, std::string &out_msg);

    bool Step3(const std::string &in_msg, std::string &out_msg);

    bool Step4(const std::string &in_msg, std::string &out_msg);

    bool export_key_share(std::string &p1_key_share_base64) const;

private:
    safeheron::zkp::dlog::DLogProof_V2 d_log_proof_Q1_;
    std::string blind_factor_;

    safeheron::zkp::pdl::PDLProver_V2 pdl_prover_;

    safeheron::curve::CurveType c_type_;
    P1KeyShare key_share_;

    safeheron::bignum::BN r_;
    safeheron::bignum::BN c_;
};

}
}
}
}


#endif //MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_KEY_GEN_P1CONTEXT_H
