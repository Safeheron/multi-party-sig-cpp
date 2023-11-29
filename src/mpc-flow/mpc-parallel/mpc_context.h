//
// Created by 何剑虹 on 2021/6/6.
//

#ifndef SAFEHERON_MPC_FLOW_MPC_PARALLEL_MPC_CONTEXT_H
#define SAFEHERON_MPC_FLOW_MPC_PARALLEL_MPC_CONTEXT_H

#include <string>
#include <utility>
#include <vector>
#include <cassert>
#include <iostream>
#include "mpc_round.h"

namespace safeheron{
namespace mpc_flow{
namespace mpc_parallel{

/**
 * Curve type
 */
enum class Role : uint32_t {
    // 0, invalid role
    INVALID_ROLE = 0,
    CoSigner1 = 1,
    CoSigner2 = 2,
    Owner = 3,
    CommonUser = 4,
};

class MPCContext {
public:
    MPCContext(int total_parties): total_parties_(total_parties), current_round_(0) {};
    virtual ~MPCContext() = default;;

private:
    void set_total_parties(int total) { total_parties_ = total; }

public:
    void RemoveAllRounds();

    void AddRound(MPCRound *round);

    bool PushMessage(const std::string &message, const std::string &party_id, int round_index_of_message);

    bool PushMessage();

    bool PopMessages(std::vector<std::string> &out_msg_arr, std::vector<std::string> &out_des_arr);

    int get_total_parties() const { return total_parties_; }

    int get_cur_round() const { return current_round_; }

    int get_total_rounds() const { return round_arr_.size(); }

    int IsOK() const { return get_last_error_code() == 0; }

    int IsCurRoundFinished() const { return round_arr_[current_round_]->IsOver(); }

    int IsFinished() const { return (current_round_ == get_total_rounds() - 1) && IsCurRoundFinished(); }

    int get_last_error_code() const;

    const char *get_last_error_info() const;

    void get_error_stack(std::vector<ErrorInfo> &error_stack) const;

    // Add virtual for embedded context
    virtual void PushErrorCode(int error_code, std::string error_info);

    // Add virtual for embedded context
    virtual void PushErrorCode(int error_code, const std::string &file_name, int line_num, const std::string &func_name,
                       const std::string &error_info);


private:
    // If there is some thing wrong in the round, information of the error will be show by '_error'
    std::vector<ErrorInfo> error_info_stack_;
    // Total mpc participators
    int total_parties_;
    int current_round_;
    std::vector<MPCRound *> round_arr_;
};

}
}
}

#endif //SAFEHERON_MPC_FLOW_MPC_PARALLEL_MPC_CONTEXT_H
