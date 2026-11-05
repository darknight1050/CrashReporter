#include "ThreadDump.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <string>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#include <unwind.h>
#include <vector>

namespace {
constexpr unsigned MaxThreads = 1024;
constexpr unsigned MaxFrames = 256;
constexpr unsigned HandlerFrames = 16;
constexpr int WaitMilliseconds = 2000;
enum State { Empty, Pending, Capturing, Ready, Failed, Cancelled };
struct Sample {
    std::atomic<int> state{Empty};
    pid_t tid = 0;
    char name[64]{};
    int error = 0;
    unsigned count = 0;
    uintptr_t interruptedPc = 0;
    uintptr_t pcs[MaxFrames + HandlerFrames]{};
};
static_assert(std::atomic<int>::is_always_lock_free);
Sample samples[MaxThreads];
std::atomic_flag requested{};
pid_t processId = 0;
int captureSignal = 0;

_Unwind_Reason_Code collect(_Unwind_Context* context, void* opaque) {
    auto& sample = *static_cast<Sample*>(opaque);
    auto pc = _Unwind_GetIP(context);
    if (pc) sample.pcs[sample.count++] = pc;
    return sample.count == MaxFrames + HandlerFrames ? _URC_END_OF_STACK : _URC_NO_REASON;
}

void handleSignal(int, siginfo_t* info, void* context) {
    int savedErrno = errno;
    auto address = reinterpret_cast<uintptr_t>(info->si_value.sival_ptr);
    auto begin = reinterpret_cast<uintptr_t>(samples);
    if (info->si_code == SI_QUEUE && info->si_pid == processId &&
        address >= begin && address < begin + sizeof(samples) && (address - begin) % sizeof(Sample) == 0) {
        auto& sample = *reinterpret_cast<Sample*>(address);
        int pending = Pending;
        if (sample.tid == gettid() && sample.state.compare_exchange_strong(pending, Capturing, std::memory_order_acquire)) {
            sample.interruptedPc = static_cast<ucontext_t*>(context)->uc_mcontext.pc;
            // Collect PCs only. Formatting, ELF lookup and logging happen on the
            // reporting thread. No Paper/Unity APIs are called here.
            _Unwind_Backtrace(collect, &sample);
            sample.state.store(Ready, std::memory_order_release);
        }
    }
    errno = savedErrno;
}

int64_t monotonicMilliseconds() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return int64_t(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

struct Module {
    uintptr_t base;
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;
    std::string name;
    std::string buildId;
};

std::vector<Module> loadedModules() {
    std::vector<Module> modules;
    dl_iterate_phdr(+[](dl_phdr_info* info, size_t, void* opaque) {
        Module module{info->dlpi_addr, {}, info->dlpi_name, {}};
        if (module.name.empty()) module.name = "/proc/self/exe";
        for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
            auto& ph = info->dlpi_phdr[i];
            if (ph.p_type == PT_LOAD) module.ranges.emplace_back(module.base + ph.p_vaddr, module.base + ph.p_vaddr + ph.p_memsz);
        }
        for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
            auto& ph = info->dlpi_phdr[i];
            if (ph.p_type != PT_NOTE) continue;
            auto start = module.base + ph.p_vaddr;
            auto end = start + ph.p_memsz;
            bool mapped = false;
            for (auto [low, high] : module.ranges) mapped |= start >= low && end <= high;
            if (!mapped) continue;
            for (auto at = start; at + sizeof(ElfW(Nhdr)) <= end;) {
                ElfW(Nhdr) note;
                std::memcpy(&note, reinterpret_cast<void*>(at), sizeof(note));
                auto name = at + sizeof(note);
                auto desc = name + ((uint64_t(note.n_namesz) + 3) & ~uint64_t(3));
                auto next = desc + ((uint64_t(note.n_descsz) + 3) & ~uint64_t(3));
                if (next > end || next <= at) break;
                if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 && std::memcmp(reinterpret_cast<void*>(name), "GNU", 4) == 0) {
                    constexpr char hex[] = "0123456789abcdef";
                    for (unsigned n = 0; n < note.n_descsz; ++n) {
                        auto byte = reinterpret_cast<unsigned char*>(desc)[n];
                        module.buildId += hex[byte >> 4];
                        module.buildId += hex[byte & 15];
                    }
                }
                at = next;
            }
        }
        static_cast<std::vector<Module>*>(opaque)->push_back(std::move(module));
        return 0;
    }, &modules);
    return modules;
}

void appendFrame(std::string& text, unsigned index, uintptr_t pc, std::vector<Module> const& modules) {
    Module const* found = nullptr;
    for (auto& module : modules) {
        for (auto [low, high] : module.ranges) {
            if (pc >= low && pc < high) { found = &module; break; }
        }
        if (found) break;
    }
    char line[96];
    std::snprintf(line, sizeof(line), "      #%02u pc %016lx  ", index, static_cast<unsigned long>(found ? pc - found->base : pc));
    text += line;
    text += found ? found->name : "<unknown executable mapping>";
    if (found && !found->buildId.empty()) text += " (BuildId: " + found->buildId + ")";
    text += '\n';
}
}

bool ThreadDump::initialize() {
    if (captureSignal) return true;
    processId = getpid();
    // Warm up the native unwinder outside any signal handler.
    _Unwind_Backtrace(+[](_Unwind_Context*, void*) { return _URC_END_OF_STACK; }, nullptr);
    struct sigaction action{};
    action.sa_sigaction = handleSignal;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    sigemptyset(&action.sa_mask);
    for (int signal = SIGRTMAX; signal >= SIGRTMIN + 6; --signal) {
        struct sigaction previous{};
        if (sigaction(signal, nullptr, &previous) != 0 || previous.sa_handler != SIG_DFL) continue;
        if (sigaction(signal, &action, nullptr) == 0) {
            captureSignal = signal;
            return true;
        }
    }
    return false;
}

std::string ThreadDump::captureOtherThreads() {
    if (!captureSignal) return "\nOther thread stacktraces unavailable: no capture signal.\n";
    if (requested.test_and_set()) return "\nOther thread capture already requested.\n";
    struct sigaction current{};
    if (sigaction(captureSignal, nullptr, &current) != 0 || !(current.sa_flags & SA_SIGINFO) || current.sa_sigaction != handleSignal)
        return "\nOther thread stacktraces unavailable: capture signal replaced.\n";
    auto directory = opendir("/proc/self/task");
    if (!directory) return "\nOther thread stacktraces unavailable: cannot enumerate threads.\n";
    unsigned count = 0;
    std::string overflow;
    const auto crashingTid = gettid();
    while (auto entry = readdir(directory)) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        auto tid = static_cast<pid_t>(std::strtol(entry->d_name, nullptr, 10));
        if (tid == crashingTid) continue;
        if (count == MaxThreads) {
            overflow += "tid: " + std::to_string(tid) + ": unavailable (thread capacity exceeded)\n";
            continue;
        }
        auto& sample = samples[count++];
        sample.tid = tid;
        char path[96];
        std::snprintf(path, sizeof(path), "/proc/self/task/%d/comm", tid);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            auto size = read(fd, sample.name, sizeof(sample.name) - 1);
            if (size > 0 && sample.name[size - 1] == '\n') sample.name[size - 1] = 0;
            close(fd);
        }
    }
    closedir(directory);
    // Resolve modules before signalling: a target may already hold the loader
    // lock. Symbol lookup is deliberately absent from the signal callback.
    auto modules = loadedModules();
    const auto deadline = monotonicMilliseconds() + WaitMilliseconds;
    for (unsigned i = 0; i < count; ++i) {
        auto& sample = samples[i];
        siginfo_t info{};
        info.si_signo = captureSignal;
        info.si_code = SI_QUEUE;
        info.si_pid = processId;
        info.si_uid = getuid();
        info.si_value.sival_ptr = &sample;
        sample.state.store(Pending, std::memory_order_release);
        if (syscall(SYS_rt_tgsigqueueinfo, processId, sample.tid, captureSignal, &info) != 0) {
            sample.error = errno;
            sample.state.store(Failed, std::memory_order_release);
        }
    }
    for (;;) {
        bool waiting = false;
        for (unsigned i = 0; i < count; ++i) {
            auto state = samples[i].state.load(std::memory_order_acquire);
            waiting |= state == Pending || state == Capturing;
        }
        if (!waiting || monotonicMilliseconds() >= deadline) break;
        timespec pause{0, 1000000};
        nanosleep(&pause, nullptr);
    }
    std::string text = "\n--- Other thread stacktraces ---\n";
    unsigned captured = 0;
    for (unsigned i = 0; i < count; ++i) {
        auto& sample = samples[i];
        text += "\npid: " + std::to_string(processId) + ", tid: " + std::to_string(sample.tid) + ", name: " + sample.name + '\n';
        int pending = Pending;
        sample.state.compare_exchange_strong(pending, Cancelled, std::memory_order_acq_rel);
        if (sample.state.load(std::memory_order_acquire) != Ready) {
            text += sample.error ? "  stacktrace unavailable: thread exited or signal failed (errno " + std::to_string(sample.error) + ")\n"
                                 : "  stacktrace unavailable: signal blocked or unwind exceeded 2000 ms\n";
            continue;
        }
        text += "backtrace:\n";
        // Drop our callback and signal trampoline. The interrupted PC is an
        // instruction address; following PCs are return addresses (minus 4).
        auto first = std::find(sample.pcs, sample.pcs + sample.count, sample.interruptedPc);
        appendFrame(text, 0, sample.interruptedPc, modules);
        if (first == sample.pcs + sample.count) {
            text += "  unwind could not cross the signal frame; interrupted PC only\n";
            continue;
        }
        unsigned frame = 1;
        for (auto pc = first + 1; pc < sample.pcs + sample.count && frame < MaxFrames; ++pc)
            appendFrame(text, frame++, *pc >= 4 ? *pc - 4 : *pc, modules);
        if (sample.count == MaxFrames + HandlerFrames || frame == MaxFrames) text += "  stacktrace truncated at 256 frames\n";
        ++captured;
    }
    text += "\nOther threads captured: " + std::to_string(captured) + "/" + std::to_string(count) + '\n';
    text += overflow;
    return text;
}
