#include "CrashWatchdog.hpp"
#include <atomic>
#include <csignal>
#include <limits>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

namespace {
int timerId = -1;
itimerspec deadline{};
std::atomic<unsigned> handlers{};
std::atomic<bool> reporting{};
constexpr unsigned ChangingTimer = std::numeric_limits<unsigned>::max();
static_assert(std::atomic<unsigned>::is_always_lock_free);
static_assert(std::atomic<bool>::is_always_lock_free);

[[noreturn]] void stop() noexcept {
    // No destructors, logging, allocation or abort hooks in a broken process.
    syscall(SYS_exit_group, 254);
    __builtin_unreachable();
}
}

bool CrashWatchdog::initialize(unsigned timeoutMilliseconds) {
    if (timerId >= 0) return true;
    if (!timeoutMilliseconds) return false;
    sigevent event{};
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGKILL;
    // Use the kernel timer ID directly: the crash path needs only a syscall,
    // never a libc timer lookup or a userspace worker that could itself stall.
    int created = -1;
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &created) != 0) return false;
    deadline.it_value.tv_sec = timeoutMilliseconds / 1000;
    deadline.it_value.tv_nsec = (timeoutMilliseconds % 1000) * 1000000L;
    timerId = created;
    return true;
}

void CrashWatchdog::enterFatal() noexcept {
    if (reporting.load(std::memory_order_acquire)) stop();
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        auto count = handlers.load(std::memory_order_acquire);
        // Do not wait on a thread interrupted while changing the timer.
        if (count >= ChangingTimer - 1) stop();
        if (!handlers.compare_exchange_weak(count, count ? count + 1 : ChangingTimer,
                std::memory_order_acq_rel)) continue;
        if (!count) {
            if (timerId < 0 || syscall(SYS_timer_settime, timerId, 0, &deadline, nullptr) != 0) stop();
            handlers.store(1, std::memory_order_release);
        }
        return;
    }
    stop();
}

void CrashWatchdog::leaveFatal() noexcept {
    // A prior handler may legitimately handle a fault and return. Do not kill
    // a recovered process later, and do not disarm another active handler.
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        auto count = handlers.load(std::memory_order_acquire);
        if (!count || count == ChangingTimer) stop();
        if (!handlers.compare_exchange_weak(count, count == 1 ? ChangingTimer : count - 1,
                std::memory_order_acq_rel)) continue;
        if (count == 1) {
            itimerspec disarmed{};
            if (syscall(SYS_timer_settime, timerId, 0, &disarmed, nullptr) != 0) stop();
            reporting.store(false, std::memory_order_release);
            handlers.store(0, std::memory_order_release);
        }
        return;
    }
    stop();
}

void CrashWatchdog::enterReport() noexcept {
    // Fallback if another mod replaced our signal wrapper after installation.
    if (!handlers.load(std::memory_order_acquire)) enterFatal();
    if (reporting.exchange(true, std::memory_order_acq_rel)) stop();
}
