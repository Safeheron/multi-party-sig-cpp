#include <thread>
#include <queue>
#ifndef MULTIPARTYECDSA_THREAD_SAFE_QUEUE_H
#define MULTIPARTYECDSA_THREAD_SAFE_QUEUE_H
template <typename T>
class ThreadSafeQueue {
private:
    //non-copyable
    std::mutex mut_;
    std::queue<T> que_;
    //non-copyable
    std::condition_variable cond_;
public:
    ThreadSafeQueue() {}
    ThreadSafeQueue(const ThreadSafeQueue& rhs) {
        que_ = rhs.que_;
    }
    ThreadSafeQueue &operator=(const ThreadSafeQueue &rhs) {
        if (&rhs != this) {
            que_ = rhs.que_;
        }
        return *this;
    }
    void Push(T value) {
        std::lock_guard<std::mutex> lk(mut_);
        que_.push(value);
        cond_.notify_one();
    }
    void Pop(T &value) {
        std::unique_lock< std::mutex> lk(mut_);
        cond_.wait(lk, [this]{return !que_.empty();});
        value = que_.front();
        que_.pop();
    }
    bool Empty() {
        std::lock_guard< std::mutex> lk(mut_);
        return que_.empty();
    }
};
#endif //MULTIPARTYECDSA_THREAD_SAFE_QUEUE_H
