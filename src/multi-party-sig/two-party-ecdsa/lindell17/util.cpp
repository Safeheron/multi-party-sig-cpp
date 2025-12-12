#include "util.h"
#include "crypto-suites/crypto-hash/sha256.h"
#include "crypto-suites/crypto-sss/vsss.h"
namespace safeheron {
namespace two_party_ecdsa {
namespace lindell17 {
bool generate_secret_share_from_dkg(const safeheron::multi_party_ecdsa::cmp::MinimalSignKey &sign_key,
                                    const std::string &remote_party_id, safeheron::bignum::BN &secret_share,
                                    safeheron::curve::CurvePoint &Q) {
    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(sign_key.X_.GetCurveType());
    std::vector <safeheron::bignum::BN> index_arr;
    int pos = sign_key.get_remote_party_pos(remote_party_id);
    if (pos == -1) return false;

    index_arr.push_back(sign_key.remote_parties_[pos].index_);
    index_arr.push_back(sign_key.local_party_.index_);
    std::vector <safeheron::bignum::BN> l_arr;
    safeheron::sss::Polynomial::GetLArray(l_arr, safeheron::bignum::BN::ZERO, index_arr, curv->n);

    secret_share = (sign_key.local_party_.x_ * l_arr.back()) % curv->n;
    Q = sign_key.X_;

    return true;
}

int compare_bytes(const std::string &left, const std::string &right) {
    size_t len = std::min(left.size(), right.size());
    for (size_t i = 0; i < len; ++i) {
        if (left[i] != right[i]) {
            return ((uint8_t) left[i] < (uint8_t) right[i]) ? -1 : 1;
        }
    }
    if (left.size() == right.size()) return 0;
    return (left.size() < right.size()) ? -1 : 1;
}

std::string make_commitment(const safeheron::curve::CurvePoint &pub,
                            const safeheron::zkp::dlog::DLogProof_V2 &dl_proof,
                            const safeheron::bignum::BN &blindness) {
    uint8_t digest[safeheron::hash::CSHA256::OUTPUT_SIZE];
    safeheron::hash::CSHA256 sha256;
    std::string buf;
    pub.x().ToBytes32BE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    pub.y().ToBytes32BE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    dl_proof.ToBase64(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    blindness.ToBytes32BE(buf);
    sha256.Write(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
    sha256.Finalize(digest);

    return std::string((const char *) digest, sizeof(digest));
}

bool check_ecdsa_curve(const safeheron::curve::CurveType &c_type) {
    if (c_type == safeheron::curve::CurveType::SECP256K1
        || c_type == safeheron::curve::CurveType::P256)
        return true;
    return false;
}
}
}
}