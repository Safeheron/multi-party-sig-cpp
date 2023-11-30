//
// Created by Sword03 on 2022/11/23.
//

#include "LazyBCValidator.h"

namespace safeheron {
namespace mpc_flow {
namespace mpc_parallel {


LazyBCValidator::LazyBCValidator(uint32_t total) {
    total_ = total;
    cached_party_id_arr_.clear();
    cached_digest_arr_.clear();
}

bool LazyBCValidator::CacheDigest(const std::string &party_id, const std::string &digest){
    if(cached_party_id_arr_.size() >= total_) return false;

    cached_party_id_arr_.push_back(party_id);
    cached_digest_arr_.push_back(digest);

    return true;
}

bool LazyBCValidator::ValidateDigest(const std::vector<std::string> &party_id_arr, const std::vector<std::string> &digest_arr, std::string &unmatched_party_id, std::string &unmatched_digest) const {
    uint32_t count = 0;

    if(party_id_arr.size() < total_) return false;

    for(size_t i = 0; i < party_id_arr.size(); ++i){
        bool is_party_found = false;
        for(size_t j = 0; j < cached_party_id_arr_.size(); ++j){
            if(party_id_arr[i] == cached_party_id_arr_[j]){
                is_party_found = true;
                if(digest_arr[i] == cached_digest_arr_[j]) {
                    count++;
                }else{
                    unmatched_party_id = party_id_arr[i];
                    unmatched_digest = digest_arr[i];
                    return false;
                }
            }
        }
        if(!is_party_found){
            unmatched_party_id = party_id_arr[i];
            unmatched_digest.clear();
            return false;
        }
    }
    return total_ == count;
}

}
}
}
