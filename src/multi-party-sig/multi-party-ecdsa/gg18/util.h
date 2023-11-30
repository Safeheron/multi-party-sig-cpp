

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_UTIL_H
#define SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_UTIL_H
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"

namespace safeheron {
namespace multi_party_ecdsa {
namespace gg18 {

bool CheckIndexArr(const std::vector<safeheron::bignum::BN> &share_index_arr, const safeheron::bignum::BN &order);

int find_party_id(std::string &party_id, const std::vector<std::string> &party_id_arr);

/**
 * In {t,n} HD Ecdsa Protocol, the hd_sign key should be pretreated in ahead if t < n.
 * @param out_sign_key_base64
 * @param in_sign_key_base64
 * @param party_id_arr. Specified all the parties that would participated in HD Ecdsa Protocol.
 * @constructor
 */
bool trim_sign_key(std::string &out_sign_key_base64, const std::string &in_sign_key_base64, const std::vector<std::string> &participant_id_arr);

}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_GG18_SIGN_UTIL_H
