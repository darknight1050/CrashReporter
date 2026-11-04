#pragma once

#include <algorithm>
#include <atomic>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

// Logging can re-enter or run on several threads. Drop a contended write or
// snapshot instead of waiting on a thread that might already have crashed.
class LogBuffer {
    std::vector<char> buffer;
    std::atomic_flag busy{};
    size_t index = 0;
    bool wrapped = false;

    // One attempt only: even same-thread reentry must skip the buffer.
    // A mutex try_lock is undefined when the calling thread already owns it.
    class TryGuard {
        std::atomic_flag& flag;
        bool acquired;

    public:
        explicit TryGuard(std::atomic_flag& flag) noexcept
            : flag(flag), acquired(!flag.test_and_set(std::memory_order_acquire)) {}
        ~TryGuard() {
            if (acquired) flag.clear(std::memory_order_release);
        }
        TryGuard(TryGuard const&) = delete;
        TryGuard& operator=(TryGuard const&) = delete;
        explicit operator bool() const noexcept { return acquired; }
    };

public:
    explicit LogBuffer(size_t size) : buffer(size) {}

    void append(std::string_view text) noexcept {
        TryGuard lock(busy);
        if (!lock || buffer.empty() || text.empty()) return;
        if (text.size() >= buffer.size()) {
            text = text.substr(text.size() - buffer.size());
            std::memcpy(buffer.data(), text.data(), text.size());
            index = 0;
            wrapped = true;
            return;
        }
        auto first = std::min(text.size(), buffer.size() - index);
        std::memcpy(buffer.data() + index, text.data(), first);
        std::memcpy(buffer.data(), text.data() + first, text.size() - first);
        wrapped = wrapped || index + text.size() >= buffer.size();
        index = (index + text.size()) % buffer.size();
    }

    std::string getData() {
        TryGuard lock(busy);
        if (!lock || buffer.empty()) return {};
        std::string data;
        if (wrapped) data.append(buffer.data() + index, buffer.size() - index);
        data.append(buffer.data(), index);
        return data;
    }
};
