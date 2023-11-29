//
// Created by Sword03 on 2023/2/24.
//

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SECURITY_PARAM_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SECURITY_PARAM_H

#include "crypto-suites/crypto-bn/bn.h"

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {

static const int SECURITY_PARAM_L = 256;

static const int SECURITY_PARAM_L_PRIME = 1280;

static const int SECURITY_PARAM_EPSILON = 512;

// I in (-2^l, 2^l)
static const safeheron::bignum::BN SECURITY_PARAM_LIMIT_I = safeheron::bignum::BN(1) << SECURITY_PARAM_L;
// J in (-2^l', 2^l')
static const safeheron::bignum::BN SECURITY_PARAM_LIMIT_J = safeheron::bignum::BN(1) << SECURITY_PARAM_L_PRIME;
// I_epsilon in (-2^(l+epsilon), 2^(l+epsilon))
static const safeheron::bignum::BN SECURITY_PARAM_LIMIT_I_EPSILON = safeheron::bignum::BN(1) << (SECURITY_PARAM_L + SECURITY_PARAM_EPSILON);
// J_epsilon in (-2^(l'+epsilon), 2^(l'+epsilon))
static const safeheron::bignum::BN SECURITY_PARAM_LIMIT_J_EPSILON = safeheron::bignum::BN(1) << (SECURITY_PARAM_L_PRIME + SECURITY_PARAM_EPSILON);

}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SECURITY_PARAM_H
