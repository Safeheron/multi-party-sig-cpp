

#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/hex.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-paillier/pail.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/sign_key.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/util.h"

using std::string;
using safeheron::bignum::BN;
using namespace safeheron::rand;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

namespace safeheron {
namespace multi_party_ecdsa {
namespace gg18 {

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

    sign_key.n_parties_ = (sign_key.remote_parties_.size() + 1);
    ok = sign_key.ValidityTest();
    if (!ok) return false;

    ok = sign_key.ToBase64(out_sign_key_base64 );
    if (!ok) return false;

    return true;
}

}
}
}