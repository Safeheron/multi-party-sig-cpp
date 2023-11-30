#ifndef SAFEHERON_CRYPTO__MTA_V2_H
#define SAFEHERON_CRYPTO__MTA_V2_H

#include <string>
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-zkp/zkp.h"

namespace safeheron {
namespace multi_party_ecdsa {
namespace gg18 {
namespace sign {

/**
 * Construct message A of MTA protocol.
 *
 * @param [out] message_a
 * @param [in] pub Paillier Public Key.
 * @param [in] input_a
 * @param [in] r_lt_pailN in (0, pailN) and gcd(r, pailN) = 1
 */
void MtA_Step1(safeheron::bignum::BN &message_a,
               const pail::PailPubKey &pub,
               const safeheron::bignum::BN &input_a,
               const safeheron::bignum::BN &r_lt_pailN);


/**
 * Construct Message B for MTA protocol and get beta where
 *      alpha + beta = input_a * input_b
 *
 * @param [out] message_b
 * @param [out] beta
 * @param [in] pub Paillier Public Key.
 * @param [in] input_b
 * @param [in] message_a
 * @param [in] beta_tag in (0, pailN)
 * @param [in] r_for_pail in (0, pailN) and gcd(r, pailN) = 1
 * @param [in] order:  order of the curve
 */
void
MtA_Step2(safeheron::bignum::BN &message_b, safeheron::bignum::BN &beta,
          const pail::PailPubKey &pub,
          const safeheron::bignum::BN &input_b,
          const safeheron::bignum::BN &message_a,
          const safeheron::bignum::BN &beta_tag,
          const safeheron::bignum::BN &r_for_pail,
          const safeheron::bignum::BN &order);

/**
 * Get alpha where
 *      alpha + beta = input_a * input_b
 *
 * @param [out] alpha
 * @param [in] message_b
 * @param [in] priv Paillier Private Key
 * @param [in] order:  order of the curve
 * @return
 */
void MtA_Step3(safeheron::bignum::BN &alpha,
               const safeheron::bignum::BN &message_b,
               const pail::PailPrivKey &priv,
               const safeheron::bignum::BN &order);

}
}
}
}

#endif //SAFEHERON_CRYPTO__MTA_V2_H
