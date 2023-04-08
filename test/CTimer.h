//
// Created by Sword03 on 2022/6/23.
//

#ifndef BLOCKCHAIN_CRYPTO_MPC_CTIMER_H
#define BLOCKCHAIN_CRYPTO_MPC_CTIMER_H

#include <string>
#include <chrono>

class CTimer {
public:
    CTimer(std::string name);
    void End();
    void Reset(std::string name);
    ~CTimer();

private:
    std::string name_;
    std::chrono::high_resolution_clock::time_point begin_;
    bool is_triggered_;
};


#endif //BLOCKCHAIN_CRYPTO_MPC_CTIMER_H
