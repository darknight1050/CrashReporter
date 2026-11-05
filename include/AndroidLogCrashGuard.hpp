#pragma once

namespace AndroidLogCrashGuard {
// Preserve existing fatal signal handlers. Resolve Android APIs at startup.
bool initialize();

// Mark the portion of logging that can still be inside ART's logger mutex.
class Scope {
public:
    Scope() noexcept;
    ~Scope();
    Scope(Scope const&) = delete;
    Scope& operator=(Scope const&) = delete;
};
}
