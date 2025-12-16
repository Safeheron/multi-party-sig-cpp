#ifndef MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_UTIL_H
#define MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_UTIL_H
#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve_point.h"
#include "crypto-suites/crypto-zkp/dlog_proof_v2.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_sign_key.h"

namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
bool generate_secret_share_from_dkg(const safeheron::multi_party_ecdsa::cmp::MinimalSignKey &sign_key,
                                    const std::string &remote_party_id, safeheron::bignum::BN &secret_share,
                                    safeheron::curve::CurvePoint &Q);

int compare_bytes(const std::string &left, const std::string &right);

std::string make_commitment(const safeheron::curve::CurvePoint &pub,
                            const safeheron::zkp::dlog::DLogProof_V2 &dl_proof,
                            const safeheron::bignum::BN &blindness);

bool check_ecdsa_curve(const safeheron::curve::CurveType &c_type);
}
}
}
#endif //MULTI_PARTY_SIG_TWO_PARTY_ECDSA_LINDELL17_UTIL_H
