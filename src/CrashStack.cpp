#include "CrashStack.hpp"

#include <atomic>
#include <cstddef>
#include <sys/mman.h>
#include <unistd.h>

namespace {
void* stackTop = nullptr;
std::atomic_flag active{};
constexpr std::size_t StackSize = 1024 * 1024;
}

extern "C" void crash_reporter_call_on_stack(void* top, void (*callback)(void*) noexcept, void* argument) noexcept;

bool CrashStack::initialize() {
    if (stackTop) return true;
    auto pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) return false;
    auto size = (StackSize + pageSize - 1) / pageSize * pageSize;
    auto mappingSize = size + 2 * pageSize;
    auto mapping = mmap(nullptr, mappingSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return false;
    auto stack = static_cast<char*>(mapping) + pageSize;
    if (mprotect(stack, size, PROT_READ | PROT_WRITE) != 0) {
        munmap(mapping, mappingSize);
        return false;
    }
    // Guard pages at both ends; keep this mapping alive until process exit.
    stackTop = stack + size;
    return true;
}

bool CrashStack::run(void (*callback)(void*) noexcept, void* argument) noexcept {
    if (!stackTop || active.test_and_set(std::memory_order_acquire)) return false;
    crash_reporter_call_on_stack(stackTop, callback, argument);
    active.clear(std::memory_order_release);
    return true;
}
