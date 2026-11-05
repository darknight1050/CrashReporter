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
    bool startsMidLine = false;

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

    void appendUnlocked(std::string_view text) noexcept {
        if (buffer.empty() || text.empty()) return;
        if (text.size() >= buffer.size()) {
            auto discarded = text.size() - buffer.size();
            if (discarded) startsMidLine = text[discarded - 1] != '\n';
            else if (wrapped || index) startsMidLine = buffer[(index + buffer.size() - 1) % buffer.size()] != '\n';
            text = text.substr(text.size() - buffer.size());
            std::memcpy(buffer.data(), text.data(), text.size());
            index = 0;
            wrapped = true;
            return;
        }
        auto length = wrapped ? buffer.size() : index;
        if (length + text.size() > buffer.size()) {
            auto discarded = length + text.size() - buffer.size();
            auto start = wrapped ? index : 0;
            startsMidLine = buffer[(start + discarded - 1) % buffer.size()] != '\n';
        }
        auto first = std::min(text.size(), buffer.size() - index);
        std::memcpy(buffer.data() + index, text.data(), first);
        std::memcpy(buffer.data(), text.data() + first, text.size() - first);
        wrapped = wrapped || index + text.size() >= buffer.size();
        index = (index + text.size()) % buffer.size();
    }

public:
    explicit LogBuffer(size_t size) : buffer(size) {}

    void append(std::string_view text) noexcept {
        TryGuard lock(busy);
        if (lock) appendUnlocked(text);
    }

    // No temporary strings or allocations in Android's logging callback.
    // Hold one guard for the whole message so concurrent prefixes cannot mix.
    void appendLog(char priority, std::string_view tag, std::string_view text) noexcept {
        TryGuard lock(busy);
        if (!lock) return;
        const char prefix[]{priority, ' '};
        do {
            auto end = text.find('\n');
            appendUnlocked(std::string_view(prefix, sizeof(prefix)));
            appendUnlocked(tag);
            appendUnlocked(": ");
            appendUnlocked(text.substr(0, end));
            appendUnlocked("\n");
            if (end == std::string_view::npos) break;
            text.remove_prefix(end + 1);
        } while (!text.empty());
    }

    std::string getData(bool completeLinesOnly = false) {
        TryGuard lock(busy);
        if (!lock || buffer.empty()) return {};
        std::string data;
        if (wrapped) data.append(buffer.data() + index, buffer.size() - index);
        data.append(buffer.data(), index);
        if (completeLinesOnly && startsMidLine) {
            auto end = data.find('\n');
            if (end == std::string::npos) data.clear();
            else data.erase(0, end + 1);
        }
        return data;
    }
};
