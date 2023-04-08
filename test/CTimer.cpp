//
// Created by Sword03 on 2022/6/23.
//

#include "CTimer.h"
#include <chrono>
#include <iostream>

CTimer::CTimer(std::string name) {
    is_triggered_ = false;
    name_ = name;
    std::cout << "Timer start ------ " << name_.c_str() << std::endl;
    begin_ = std::chrono::high_resolution_clock::now();
}

void CTimer::Reset(std::string name) {
    is_triggered_ = false;
    name_ = name;
    std::cout << "Timer reset ------ " << name_.c_str() << std::endl;
    begin_ = std::chrono::high_resolution_clock::now();
}

void CTimer::End() {
    if(!is_triggered_){
        std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end - begin_;
        std::cout << "Timer end ------ " << name_.c_str() << " " << std::chrono::duration<double>(duration).count() << std::endl;
        is_triggered_ = true;
    }
}

CTimer::~CTimer() {
    if(!is_triggered_){
        std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end - begin_;
        std::cout << "Timer end ------ " << name_.c_str() << " " << std::chrono::duration<double>(duration).count() << std::endl;
    }
}