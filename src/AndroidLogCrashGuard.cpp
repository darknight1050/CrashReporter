#include "AndroidLogCrashGuard.hpp"
#include <android/log.h>
#include <csignal>
#include <dlfcn.h>

namespace {
thread_local volatile sig_atomic_t loggingDepth = 0;
using Logger = void (*)(__android_log_message const*);
using SetLogger = void (*)(Logger);
SetLogger setLogger = nullptr;
Logger logdLogger = nullptr;
constexpr int signals[]{SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE};
struct sigaction previous[sizeof(signals) / sizeof(*signals)]{};

void fatalSignal(int signal, siginfo_t* info, void* context) {
    // A crash inside ART's logging callback leaves its logger mutex held.
    // Unity's fatal handler logs before reaching engrave_tombstone. Route those
    // messages straight to logd so it cannot re-enter the interrupted logger.
    // Android's setter only assigns a function pointer; no lookup or allocation.
    // Keep this route until the fatal handler terminates the process.
    if (loggingDepth) setLogger(logdLogger);
    for (unsigned i = 0; i < sizeof(signals) / sizeof(*signals); ++i) {
        if (signals[i] != signal) continue;
        auto const& action = previous[i];
        if (action.sa_flags & SA_SIGINFO) action.sa_sigaction(signal, info, context);
        else action.sa_handler(signal);
        return;
    }
}
}

bool AndroidLogCrashGuard::initialize() {
    setLogger = reinterpret_cast<SetLogger>(dlsym(RTLD_DEFAULT, "__android_log_set_logger"));
    logdLogger = reinterpret_cast<Logger>(dlsym(RTLD_DEFAULT, "__android_log_logd_logger"));
    if (!setLogger || !logdLogger) return false;
    bool complete = true;
    for (unsigned i = 0; i < sizeof(signals) / sizeof(*signals); ++i) {
        struct sigaction action{};
        if (sigaction(signals[i], nullptr, &action) != 0) { complete = false; continue; }
        if ((action.sa_flags & SA_SIGINFO) && action.sa_sigaction == fatalSignal) continue;
        // Never turn an ignored/default signal into a returning handler.
        if (action.sa_handler == SIG_DFL || action.sa_handler == SIG_IGN) {
            complete = false;
            continue;
        }
        previous[i] = action;
        action.sa_sigaction = fatalSignal;
        action.sa_flags |= SA_SIGINFO;
        // Retain the original mask, alternate-stack and one-shot semantics.
        if (sigaction(signals[i], &action, nullptr) != 0) complete = false;
    }
    return complete;
}

AndroidLogCrashGuard::Scope::Scope() noexcept { loggingDepth = loggingDepth + 1; }
AndroidLogCrashGuard::Scope::~Scope() { loggingDepth = loggingDepth - 1; }
