#pragma once

namespace CrashStack {
// Allocate before installing the crash hook, never from a signal handler.
bool initialize();
// Keep the crashing thread and its signal context, but use a larger stack.
// Concurrent/nested requests are skipped instead of waiting on the crash thread.
bool run(void (*callback)(void*) noexcept, void* argument) noexcept;
}
