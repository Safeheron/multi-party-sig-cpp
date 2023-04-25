#ifndef MULTIPARTYECDSA_PARTY_MESSAGE_QUEUE_H
#define MULTIPARTYECDSA_PARTY_MESSAGE_QUEUE_H

#include "thread_safe_queue.h"
#include <vector>

template <typename T>
class PartyMessageQue {
public:
    PartyMessageQue() {}
    PartyMessageQue(int rounds) {
        for (int i = 0; i < rounds; i++) {
            queues.push_back(ThreadSafeQueue<T>());
        }
    }
    ~PartyMessageQue() {}
    ThreadSafeQueue<T>& get(size_t round) {
        assert(round < queues.size());
        return queues[round];
    }
private:
    std::vector<ThreadSafeQueue<T>> queues;
};

#endif //MULTIPARTYECDSA_PARTY_MESSAGE_QUEUE_H