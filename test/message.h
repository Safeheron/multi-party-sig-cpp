#include<string>
#ifndef MULTIPARTYECDSA_MESSAGE_H
#define MULTIPARTYECDSA_MESSAGE_H
typedef struct Msg {
    std::string src_;
    std::string bc_msg_;
    std::string p2p_msg_;
} Msg;
#endif //MULTIPARTYECDSA_MESSAGE_H
