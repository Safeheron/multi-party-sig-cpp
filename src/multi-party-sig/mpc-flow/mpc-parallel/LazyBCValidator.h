//
// Created by Sword03 on 2022/11/23.
//

#ifndef SAFEHERON_MPC_FLOW_MPC_PARALLEL_LAZYBCVALIDATER_H
#define SAFEHERON_MPC_FLOW_MPC_PARALLEL_LAZYBCVALIDATER_H

#include <string>
#include <vector>

namespace safeheron {
namespace mpc_flow {
namespace mpc_parallel {

class LazyBCValidator {
public:
    LazyBCValidator(uint32_t total);

    LazyBCValidator(){}

    void SetTotal(uint32_t total){ total_ = total; }

    bool CacheDigest(const std::string &party_id, const std::string &digest);

    bool ValidateDigest(const std::vector <std::string> &party_id_arr,
                        const std::vector <std::string> &digest_arr,
                        std::string &unmatched_party_id,
                        std::string &unmatched_digest) const;

private:
    std::vector <std::string> cached_party_id_arr_;
    std::vector <std::string> cached_digest_arr_;
    uint32_t total_;
};

}
}
}


#endif //SAFEHERON_MPC_FLOW_MPC_PARALLEL_LAZYBCVALIDATER_H
