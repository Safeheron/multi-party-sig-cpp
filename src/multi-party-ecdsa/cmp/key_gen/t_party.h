#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_T_PARTY_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_T_PARTY_H
#include "crypto-suites/crypto-bn/bn.h"
namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {
namespace key_gen {
class LocalTParty {
public:
    LocalTParty() : prepared_(false) {}
public:
    bool prepared_;
    safeheron::bignum::BN N_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN p_;
    safeheron::bignum::BN q_;

    safeheron::bignum::BN alpha_;
    safeheron::bignum::BN beta_;
};
}
}
}
}
#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_KEY_GEN_T_PARTY_H
