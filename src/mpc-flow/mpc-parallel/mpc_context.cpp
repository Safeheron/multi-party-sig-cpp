//
// Created by 何剑虹 on 2021/6/6.
//

#include <string>
#include <utility>
#include <vector>
#include <cassert>
#include "mpc_context.h"

namespace safeheron{
namespace mpc_flow{
namespace mpc_parallel{

void MPCContext::RemoveAllRounds() {
    round_arr_.clear();
}

void MPCContext::AddRound(MPCRound *round) {
    round->set_total_parties(total_parties_);
    round->set_round_index(round_arr_.size());
    round->set_mpc_context(this);
    if(!round->is_initiated()){
        round->Init();
        round->set_initiated();
    }
    round_arr_.push_back(round);
}

bool MPCContext::PushMessage(const std::string &message, const std::string &party_id, int round_index_of_message) {
    assert(IsOK() && !IsFinished());
    if (IsCurRoundFinished()) current_round_++;
    int error_code;
    std::string error_msg;
    bool ok = round_arr_[current_round_]->InternalPushMessage(message, round_index_of_message, party_id, error_code, error_msg);
    if (!ok) {
        // Error information from internal context
        PushErrorCode(error_code, error_msg);
        // Error information from current context
        PushErrorCode(error_code, __FILE__, __LINE__, __FUNCTION__, "InternalPushMessage failed!");
    }
    return ok;
}

bool MPCContext::PushMessage() {
    assert(current_round_ == 0);
    int error_code;
    std::string error_msg;
    bool ok = round_arr_[current_round_]->InternalPushMessage(error_code, error_msg);
    if (!ok) {
        // Error information from internal context
        PushErrorCode(error_code, error_msg);
        // Error information from current context
        PushErrorCode(error_code, __FILE__, __LINE__, __FUNCTION__, "InternalPushMessage failed!");
    }
    return ok;
}

bool MPCContext::PopMessages(std::vector<std::string> &out_msg_arr, std::vector<std::string> &out_des_arr) {
    assert(IsOK());
    int error_code;
    std::string error_msg;
    bool ok = round_arr_[current_round_]->InternalPopMessages(out_msg_arr, out_des_arr, error_code, error_msg);
    if (!ok) {
        // Error information from internal context
        PushErrorCode(error_code, error_msg);
        // Error information from current context
        PushErrorCode(error_code, __FILE__, __LINE__, __FUNCTION__, "InternalPopMessages failed!");
    }
    return ok;
}

int MPCContext::get_last_error_code() const {
    if (error_info_stack_.empty()) return 0;
    size_t last = error_info_stack_.size() - 1;
    return error_info_stack_[last].code_;
}

const char * MPCContext::get_last_error_info() const {
    if (error_info_stack_.empty()) return "";
    size_t last = error_info_stack_.size() - 1;
    return error_info_stack_[last].info_.c_str();
}

void MPCContext::get_error_stack(std::vector<ErrorInfo> &error_stack) const {
    for(const auto &err:  error_info_stack_){
        error_stack.push_back(err);
    }
}

// Add virtual for embedded context
void MPCContext::PushErrorCode(int error_code, std::string error_info) {
    ErrorInfo error;
    error.code_ = error_code;
    error.info_ = std::move(error_info);
    error_info_stack_.push_back(error);
}

// Add virtual for embedded context
void MPCContext::PushErrorCode(int error_code, const std::string &file_name, int line_num, const std::string &func_name,
                   const std::string &error_info) {
    ErrorInfo error;
    error.code_ = error_code;
    std::string str;
    str.reserve(100);
    str.append(file_name);
    str.append(":");
    str.append(std::to_string(line_num));
    str.append(":");
    str.append(func_name);
    str.append(":");
    str.append(error_info);
    error.info_ = std::move(str);
    error_info_stack_.push_back(error);
}

}
}
}
