//
// Created by 何剑虹 on 2021/6/6.
//

#include "mpc_round.h"
#include <string>
#include <vector>
#include <cassert>

namespace safeheron{
namespace mpc_flow{
namespace mpc_parallel{

class MPCContext;

std::string MPCRound::make_error_msg(int error_code_, const std::string &file_name, int line_num, const std::string &func_name,
                           const std::string &error_description){
    std::string str;
    str.reserve(100);
    str.append(file_name);
    str.append(":");
    str.append(std::to_string(line_num));
    str.append(":");
    str.append(error_description);
    return str;
}

bool MPCRound::InternalPushMessage(int &error_code, std::string &error_msg) {
    assert(round_index_ == 0);
    bool ok = true;
    ok = ComputeVerify();
    if (!ok) {
        error_code = 1;
        error_msg = make_error_msg(1, __FILE__, __LINE__, __FUNCTION__, "ComputeVerify failed!");
        return false;
    }
    ok = MakeMessage(out_message_arr_, out_des_arr_);
    if (!ok) {
        error_code = 1;
        error_msg = make_error_msg(1, __FILE__, __LINE__, __FUNCTION__, "MakeMessage failed!");
        return false;
    }
    is_finished_ = true;
    return true;
}

bool MPCRound::InternalPushMessage(const std::string &msg, int round_index, std::string party_id, int &error_code, std::string &error_msg) {
    assert(round_index_ != 0);
    bool ok = true;
    if (round_index_ != (round_index + 1)) {
        char ch[100];
        snprintf(ch, 100, "Need message from round %d, but not round %d !", round_index_ - 1, round_index);
        error_code = 1;
        error_msg = make_error_msg(1, __FILE__, __LINE__, __FUNCTION__, ch);
        return false;
    }

    // Receive message
    ok = ParseMsg(msg, party_id);
    if (!ok) {
        error_code = 1;
        error_msg = make_error_msg(1, __FILE__, __LINE__, __FUNCTION__, "ParseMsg failed!");
        return false;
    }
    ok = ReceiveVerify(party_id);
    if (!ok) {
        error_code = 1;
        error_msg = make_error_msg(1, __FILE__, __LINE__, __FUNCTION__, "ReceiveVerify failed!");
        return false;
    }
    msg_count_++;

    // If all messages were received.
    if (msg_count_ == total_parties_ - 1) {
        ok = ComputeVerify();
        if (!ok) {
            error_code = 1;
            error_msg = make_error_msg(1, __FILE__, __LINE__, __FUNCTION__, "ComputeVerify failed!");
            return false;
        }
        ok = MakeMessage(out_message_arr_, out_des_arr_);
        if (!ok) {
            error_code = 1;
            error_msg = make_error_msg(1, __FILE__, __LINE__, __FUNCTION__, "MakeMessage failed!");
            return false;
        }
        is_finished_ = true;
    }

    return true;
}

bool MPCRound::InternalPopMessages(std::vector<std::string> &out_msg_arr, std::vector<std::string> &out_des_arr, int &error_code, std::string &error_msg) {
    out_msg_arr.insert(out_msg_arr.begin(), out_message_arr_.begin(), out_message_arr_.end());
    out_des_arr.insert(out_des_arr.begin(), out_des_arr_.begin(), out_des_arr_.end());
    return true;
}

}
}
}
