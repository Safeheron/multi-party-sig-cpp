#ifndef MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_P2CONTEXT_H
#define MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_P2CONTEXT_H
#include "multi-party-sig/two-party-ecdsa/lindell17/P2KeyShare.h"

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
namespace sign {
class P2Context {
public:
    P2Context() : c_type_(safeheron::curve::CurveType::INVALID_CURVE) {}

    bool CreateContext(const safeheron::curve::CurveType &c_type,
                        const std::string &p2_key_share_base64,
                        const safeheron::bignum::BN &m);

public:
    // Add extra step0 to negotiate sid with P1
    bool Step0(const std::string &in_msg, std::string &out_msg);

    bool Step1(const std::string &in_msg, std::string &out_msg);

    bool Step2(const std::string &in_msg, std::string &out_msg);

private:
    std::string sid1_commitment_;
    std::string zk_pk_commmitment_;

    safeheron::curve::CurveType c_type_;
    safeheron::bignum::BN m_;
    P2KeyShare key_share_;

    safeheron::bignum::BN k2_;
    safeheron::bignum::BN k2_prime_;
    safeheron::curve::CurvePoint R_;

    std::string sid2_;
    std::string sid_;
};
}
}
}
}


#endif //MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_SIGN_P2CONTEXT_H
