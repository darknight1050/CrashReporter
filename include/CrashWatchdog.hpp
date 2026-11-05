#pragma once

namespace CrashWatchdog {
// Allocate one disarmed kernel timer while healthy. Shorter deadlines are for tests.
bool initialize(unsigned timeoutMilliseconds = 10000);
// Called around the existing fatal signal handler. Nested entries share a deadline.
void enterFatal() noexcept;
void leaveFatal() noexcept;
// Once reporting starts, another fatal fault must not recurse into the reporter.
void enterReport() noexcept;
}
