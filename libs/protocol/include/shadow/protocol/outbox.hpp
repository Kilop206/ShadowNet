#pragma once
#include <shadow/protocol/tunnel.hpp>
#include <deque>
#include <memory>

namespace shadow::protocol::tunnel {
// The active frame is immutable until async_write completes. Control messages
// have reserved capacity and overtake queued data, never the active frame.
class Outbox {
public:
    static constexpr std::size_t data_limit = 4 * max_message;
    static constexpr std::size_t session_reservation = 8 * max_message;
    bool push(const Frame& frame) {
        // CANCEL stays behind REQUEST frames: overtaking one could start work
        // after its cancellation was already consumed by the agent.
        const bool control = frame.type <= Type::goodbye;
        const auto size = frame.payload.size() + 12;
        if (control ? control_count_ >= 8 || size > control_message : data_count_ >= 56 || size > data_limit - data_bytes_) return false;
        auto bytes = std::make_shared<const std::vector<std::uint8_t>>(encode(frame));
        (control ? control_ : data_).push_back(bytes);
        if (control) ++control_count_;
        else { ++data_count_; data_bytes_ += bytes->size(); }
        return true;
    }
    std::shared_ptr<const std::vector<std::uint8_t>> front() {
        if (!active_) {
            active_control_ = !control_.empty();
            auto& queue = active_control_ ? control_ : data_;
            active_ = queue.front(); queue.pop_front();
        }
        return active_;
    }
    void pop() {
        if (active_control_) --control_count_;
        else { --data_count_; data_bytes_ -= active_->size(); }
        active_.reset();
    }
    bool empty() const { return control_count_ + data_count_ == 0; }
    std::size_t data_bytes() const { return data_bytes_; }
    void clear() {
        control_.clear(); data_.clear(); active_.reset();
        control_count_ = data_count_ = data_bytes_ = 0;
    }
private:
    std::deque<std::shared_ptr<const std::vector<std::uint8_t>>> control_, data_;
    std::shared_ptr<const std::vector<std::uint8_t>> active_;
    std::size_t control_count_ = 0, data_count_ = 0, data_bytes_ = 0;
    bool active_control_ = false;
};
} // namespace shadow::protocol::tunnel
