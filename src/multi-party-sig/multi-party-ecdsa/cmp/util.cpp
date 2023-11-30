#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "crypto-suites/crypto-sss/polynomial.h"
#include "crypto-suites/crypto-hash/sha256.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/minimal_sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/sign_key.h"
#include "multi-party-sig/mpc-flow/common/sid_maker.h"
#include "multi-party-sig/multi-party-ecdsa/cmp/util.h"

using safeheron::multi_party_ecdsa::cmp::SignKey;
using safeheron::mpc_flow::common::SIDMaker;

using std::string;
using safeheron::bignum::BN;
using namespace safeheron::rand;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

namespace safeheron {
namespace multi_party_ecdsa {
namespace cmp {

bool CheckIndexArr(const std::vector<BN> &share_index_arr, const BN &order){
    for(size_t i = 0; i < share_index_arr.size(); ++i){
        BN t_index = share_index_arr[i] % order;
        if( t_index == 0 ) return false;
    }
    for(size_t i = 0; i < share_index_arr.size(); ++i){
        for(size_t k = 0; k < share_index_arr.size(); ++k){
            BN left = share_index_arr[i] % order;
            BN right = share_index_arr[k] % order;
            if( ( i != k ) && ( left == right ) ) return false;
        }
    }
    return true;
}

int find_party_id(std::string &party_id, const std::vector<std::string> &party_id_arr){
    int ret = -1;
    for(size_t i = 0; i < party_id_arr.size(); ++i){
        if(party_id.compare(party_id_arr[i]) == 0){
            ret = i;
            break;
        }
    }
    return ret;
}

int compare_bytes(const std::string &left, const std::string &right){
    size_t len = std::min(left.size(), right.size());
    for(size_t i = 0; i < len; ++i){
        if(left[i] != right[i]) {
            return ((uint8_t)left[i] < (uint8_t)right[i]) ? -1 : 1;
        }
    }
    if(left.size() == right.size()) return 0;
    return (left.size() < right.size()) ? -1 : 1;
}

bool trim_sign_key(std::string &out_sign_key_base64, const std::string &in_sign_key_base64, const std::vector<std::string> &participant_id_arr){
    bool ok = true;
    SignKey sign_key;
    ok = sign_key.FromBase64(in_sign_key_base64);
    if(!ok) return false;

    ok = (find_party_id(sign_key.local_party_.party_id_, participant_id_arr) != -1);
    if(!ok) return false;

    auto iter = sign_key.remote_parties_.begin();
    while(iter != sign_key.remote_parties_.end()){
        bool found = (find_party_id((*iter).party_id_, participant_id_arr) != -1);
        if(found){
            ++iter;
        }else{
            iter = sign_key.remote_parties_.erase(iter);
        }
    }

    ok = (sign_key.threshold_ <= (sign_key.remote_parties_.size() + 1));
    if(!ok) return false;

    sign_key.n_parties_ = sign_key.remote_parties_.size() + 1;
    ok = sign_key.ValidityTest();
    if (!ok) return false;

    ok = sign_key.ToBase64(out_sign_key_base64 );
    if (!ok) return false;

    return true;
}

bool prepare_data(safeheron::bignum::BN &N,
                             safeheron::bignum::BN &s,
                             safeheron::bignum::BN &t,
                             safeheron::bignum::BN &p,
                             safeheron::bignum::BN &q,
                             safeheron::bignum::BN &alpha,
                             safeheron::bignum::BN &beta) {
    safeheron::zkp::dln_proof::GenerateN_tilde(N, s, t, p, q, alpha, beta);
    return true;
}

std::string get_err_info(safeheron::mpc_flow::mpc_parallel_v2::MPCContext *ctx) {
    std::vector<safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo> error_stack;
    ctx->get_error_stack(error_stack);
    std::string err_info;
    for (size_t i = 0; i < error_stack.size(); ++i) {
        err_info += error_stack[i].info_;
        err_info += "\n";
    }
    return err_info;
}

}
}
}