

#ifndef SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_UTIL_H
#define SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_UTIL_H
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-zkp/two_dln_proof.h"
#include "crypto-suites/crypto-zkp/pail/pail_blum_modulus_proof.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "multi-party-sig/mpc-flow/mpc-parallel-v2/mpc_context.h"

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {

bool CheckIndexArr(const std::vector<safeheron::bignum::BN> &share_index_arr, const safeheron::bignum::BN &order);

int find_party_id(std::string &party_id, const std::vector<std::string> &party_id_arr);

int compare_bytes(const std::string &left, const std::string &right);

/**
 * In {t,n} HD Ecdsa Protocol, the sign key should be pretreated in ahead if t < n.
 * @param out_sign_key_base64
 * @param in_sign_key_base64
 * @param party_id_arr. Specified all the parties that would participated in HD Ecdsa Protocol.
 * @constructor
 */
bool trim_sign_key(std::string &out_sign_key_base64, const std::string &in_sign_key_base64,
                   const std::vector<std::string> &participant_id_arr);

bool prepare_data(safeheron::bignum::BN &N,
                        safeheron::bignum::BN &s,
                        safeheron::bignum::BN &t,
                        safeheron::bignum::BN &p,
                        safeheron::bignum::BN &q,
                        safeheron::bignum::BN &alpha,
                        safeheron::bignum::BN &beta);

std::string get_err_info(safeheron::mpc_flow::mpc_parallel_v2::MPCContext *ctx);

}
}
}

#endif //SAFEHERON_MULTI_PARTY_ECDSA_CMP_SIGN_UTIL_H
