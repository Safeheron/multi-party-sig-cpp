#ifndef MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_P1CONTEXT_H
#define MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_P1CONTEXT_H
#include "multi-party-sig/two-party-ecdsa/lindell17/P1KeyShare.h"
#include "crypto-suites/crypto-zkp/dlog_proof_v2.h"

namespace safeheron{
namespace two_party_ecdsa {
namespace lindell17 {
namespace sign {
class P1Context {
public:
    P1Context() : c_type_(safeheron::curve::CurveType::INVALID_CURVE), v_(0) {}

    bool CreateContext(const safeheron::curve::CurveType &c_type,
                        const std::string &p1_key_share_base64,
                        const safeheron::bignum::BN &m);

public:
    // Add extra step0 to negotiate sid with P2
    bool Step0(std::string &out_msg);

    bool Step1(const std::string &in_msg, std::string &out_msg);

    bool Step2(const std::string &in_msg, std::string &out_msg);

    bool Step3(const std::string &in_msg);

    bool export_sig(uint8_t *sig64, uint32_t &v) const;

private:
    safeheron::zkp::dlog::DLogProof_V2 d_log_proof_R1_;
    std::string sid1_blind_factor_;
    std::string zk_pk_blind_factor_;

    safeheron::curve::CurveType c_type_;

    safeheron::bignum::BN m_;
    P1KeyShare key_share_;

    safeheron::bignum::BN k1_;
    safeheron::curve::CurvePoint R_;

    safeheron::bignum::BN t_;

    std::string sid1_;
    std::string sid_;

    safeheron::bignum::BN r_;
    safeheron::bignum::BN s_;
    uint32_t v_;
};
}
}
}
}


#endif //MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_P1CONTEXT_H
