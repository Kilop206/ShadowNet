#pragma once
#include <cstddef>
#include <functional>
#include <memory>
#include <utility>

namespace shadow {
// Confined to one executor. Reservations outlive cancelled I/O until its last
// handler releases the buffers; this prevents premature reuse after reconnect.
class BufferBudget {
    struct State {
        std::size_t capacity, used = 0, peak = 0;
        std::function<void()> released;
    };
public:
    class Lease {
    public:
        Lease(std::shared_ptr<State> state, std::size_t bytes) : state_(std::move(state)), bytes_(bytes) {}
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        ~Lease() {
            state_->used -= bytes_;
            if (state_->released) state_->released();
        }
    private:
        std::shared_ptr<State> state_;
        std::size_t bytes_;
    };
    explicit BufferBudget(std::size_t capacity) : state_(std::make_shared<State>(State{capacity, 0, 0, {}})) {}
    std::shared_ptr<Lease> acquire(std::size_t bytes) {
        if (bytes == 0 || bytes > state_->capacity - state_->used) return {};
        auto lease = std::make_shared<Lease>(state_, bytes);
        state_->used += bytes;
        if (state_->used > state_->peak) state_->peak = state_->used;
        return lease;
    }
    void on_release(std::function<void()> callback) { state_->released = std::move(callback); }
    std::size_t used() const { return state_->used; }
    std::size_t peak() const { return state_->peak; }
    std::size_t capacity() const { return state_->capacity; }
private:
    std::shared_ptr<State> state_;
};
} // namespace shadow
