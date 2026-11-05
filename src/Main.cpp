#include "beatsaber-hook/shared/utils/utils.h"
#include "beatsaber-hook/shared/utils/hooking.hpp"

#include "scotland2/shared/loader.hpp"

#include "CustomLogger.hpp"
#include "ModConfig.hpp"
#include "ModSettingsViewController.hpp"
#include "UnityCrashHandlerPatterns.hpp"
#include "UnityEngine/SystemInfo.hpp"
#include "UnityEngine/Application.hpp"
#include "LogBuffer.hpp"
#include "Gzip.hpp"
#include "CrashStack.hpp"
#include "AndroidLogCrashGuard.hpp"

#include "libcurl/shared/curl.h"
#include "libcurl/shared/easy.h"
#include "bsml/shared/BSML.hpp"
#include <sys/mman.h>
#include <sstream>
#include <iomanip>
#include <android/log.h>
#include <cerrno>
#include <unistd.h>
#include <memory>
#include <link.h>

constexpr long UploadTimeoutMs = 3000L;
#define USER_AGENT (std::string("CrashReporter/") + VERSION + " (+https://github.com/darknight1050/CrashReporter)").c_str()

std::string LibIl2CppBuildID = "not_found";
std::string GameVersion;

modloader::ModInfo modInfo = {MOD_ID, VERSION, 0};

std::string query_encode(const std::string& s) {
    std::string ret;
    #define IS_BETWEEN(ch, low, high) (ch >= low && ch <= high)
    #define IS_ALPHA(ch) (IS_BETWEEN(ch, 'A', 'Z') || IS_BETWEEN(ch, 'a', 'z'))
    #define IS_DIGIT(ch) IS_BETWEEN(ch, '0', '9')
    #define IS_HEXDIG(ch) (IS_DIGIT(ch) || IS_BETWEEN(ch, 'A', 'F') || IS_BETWEEN(ch, 'a', 'f'))
    for(size_t i = 0; i < s.size();)
    {
        char ch = s[i++];
        if (IS_ALPHA(ch) || IS_DIGIT(ch))
        {
            ret += ch;
        }
        else if ((ch == '%') && i + 1 < s.size() && IS_HEXDIG(s[i+0]) && IS_HEXDIG(s[i+1]))
        {
            ret += s.substr(i-1, 3);
            i += 2;
        }
        else
        {
            switch (ch)
            {
                case '-':
                case '.':
                case '_':
                case '~':
                case '!':
                case '$':
                case '&':
                case '\'':
                case '(':
                case ')':
                case '*':
                case '+':
                case ',':
                case ';':
                case '=':
                case ':':
                case '@':
                case '/':
                case '?':
                case '[':
                case ']':
                    ret += ch;
                    break;
                default:
                {
                    static const char hex[] = "0123456789ABCDEF";
                    char pct[] = "%  ";
                    pct[1] = hex[(ch >> 4) & 0xF];
                    pct[2] = hex[ch & 0xF];
                    ret.append(pct, 3);
                    break;
                }
            }
        }
    }
    return ret;
}

std::string escape_json(const std::string &s) {
    std::ostringstream o;
    for (auto c = s.cbegin(); c != s.cend(); c++) {
        switch (*c) {
        case '"': o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b"; break;
        case '\f': o << "\\f"; break;
        case '\n': o << "\\n"; break;
        case '\r': o << "\\r"; break;
        case '\t': o << "\\t"; break;
        default:
            if ('\x00' <= *c && *c <= '\x1f') {
                o << "\\u"
                  << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(*c);
            } else {
                o << *c;
            }
        }
    }
    return o.str();
}

std::string readFD(int fd) {
    std::string data;
    const int bufSize = 4096;
    char buf[bufSize];
    ssize_t size = 0;
    do {
        size = read(fd, buf, bufSize);
        if(size > 0)
            data.append(buf, size);
    } while (size > 0);
    return data;
}

LogBuffer buffer(0x20000);

struct ReportRequest {
    std::string url;
    std::string userId;
    std::string type;
    std::string payload;
};

// Snapshot configuration, log text and mod metadata on the calling thread.
// The upload request owns its native strings.
ReportRequest captureReport(std::string const& stacktrace, std::string type) {
    ReportRequest request{getModConfig().Url.GetValue(), getModConfig().UserId.GetValue(), std::move(type), {}};
    auto& data = request.payload;
    data = "{\"userId\":\"" + escape_json(request.userId) + "\",\"libIl2CppBuildID\":\"" + escape_json(LibIl2CppBuildID)
        + "\",\"gameVersion\":\"" + escape_json(GameVersion)
        + "\",\"stacktrace\":\"" + escape_json(stacktrace) + "\"";
    if (getModConfig().Log.GetValue()) {
        auto log = buffer.getData(true);
        data += ",\"log\":\"" + escape_json(log) + "\"";
    }
    data += ",\"mods\":[";
    auto mods = modloader_get_loaded();
    struct ReleaseMods {
        decltype(mods)* results;
        ~ReleaseMods() { modloader_free_results(results); }
    } releaseMods{&mods};
    bool first = true;
    for (auto const& mod : std::span<CModResult const>(mods.array, mods.size)) {
        if (!first) data += ',';
        first = false;
        auto const& info = mod.info;
        data += "{\"name\":\"" + escape_json(info.id ? info.id : "") + "\",\"version\":\""
            + escape_json(info.version ? info.version : "") + "\",\"version_long\":" + std::to_string(info.version_long) + "}";
    }
    data += "]}";
    return request;
}

void uploadReport(ReportRequest const& request) {
    LOG_INFO("Uploading {} to: {}", request.type, request.url);
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) {
        LOG_ERROR("Could not initialize the {} upload", request.type);
        return;
    }
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
        curl_slist_append(nullptr, "Content-Type: application/json"), curl_slist_free_all);
    if (!headers) {
        LOG_ERROR("Could not allocate upload headers");
        return;
    }
    std::string compressed;
    std::string_view body = request.payload;
    if (gzipCompress(request.payload, compressed)) {
        auto updated = curl_slist_append(headers.get(), "Content-Encoding: gzip");
        if (!updated) {
            LOG_ERROR("Could not allocate gzip upload header");
            return;
        }
        headers.release();
        headers.reset(updated);
        body = compressed;
    } else {
        LOG_INFO("Could not compress crash report; uploading original JSON");
    }
    std::string response;
    char error[CURL_ERROR_SIZE]{};
    auto handle = curl.get();
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(handle, CURLOPT_URL, query_encode(request.url).c_str());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
    curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, UploadTimeoutMs);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, UploadTimeoutMs);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, error);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION,
        +[](char* bytes, std::size_t size, std::size_t count, std::string* output) noexcept -> std::size_t {
            auto length = size * count;
            // A report response is an ID, not an unbounded download.
            if (length > 64 * 1024 - output->size()) return 0;
            try {
                output->append(bytes, length);
                return length;
            } catch (...) {
                return 0;
            }
        });
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(handle, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
    auto result = curl_easy_perform(handle);
    if (result == CURLE_OK) {
        long httpCode = 0;
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &httpCode);
        if (httpCode == 200) {
            LOG_INFO("Uploaded {} with crashId: {} and userId: {}", request.type, response, request.userId);
        } else {
            LOG_ERROR("Uploading {} failed: {}: {}", request.type, httpCode, response);
        }
    } else {
        LOG_ERROR("Uploading {} failed: {}: {}", request.type, static_cast<long>(result), error[0] ? error : curl_easy_strerror(result));
    }
}

void uploadTombstone(int* tombstone_fd, void* param_3) {
    if (!getModConfig().Enabled.GetValue()) return;
    auto crashText = param_3 ? *reinterpret_cast<char**>(param_3) : nullptr;
    std::string trace = crashText ? crashText : "(no native backtrace)";
    bool fullCrash = getModConfig().FullCrash.GetValue();
    if (fullCrash && tombstone_fd && *tombstone_fd >= 0 && lseek(*tombstone_fd, 0, SEEK_SET) >= 0) {
        auto tombstone = readFD(*tombstone_fd);
        if (!tombstone.empty()) trace = std::move(tombstone);
        else trace = "Fallback to normal crash:\n" + trace;
    }
    Paper::Logger::WaitForFlushTimeout(50);
    uploadReport(captureReport(trace, fullCrash ? "tombstone" : "crash"));
}

MAKE_HOOK_NO_CATCH(engrave_tombstone, (nullptr), void, int* tombstone_fd, int* param_2, void* param_3, void* param_4, int param_5, void* param_6, void* param_7, void* param_8) {
    struct Arguments {
        int* fd; int* fd2; void* context; void* threads; int tid;
        void* process; void* files; void* text;
    } args{tombstone_fd, param_2, param_3, param_4, param_5, param_6, param_7, param_8};
    // Android's 32 KiB alternate signal stack is too small for Unity's dump
    // plus ART's log formatting. Overflow there re-enters the logger while its
    // mutex is held. Switch before calling Unity, preserving this thread/TID.
    CrashStack::run(+[](void* opaque) noexcept {
        auto& a = *static_cast<Arguments*>(opaque);
        engrave_tombstone(a.fd, a.fd2, a.context, a.threads, a.tid, a.process, a.files, a.text);
        uploadTombstone(a.fd, a.context);
    }, &args);
}

char getPriorityChar(int priority) {
    constexpr char priorities[] = "U VDIWEFS";
    return priority >= 0 && priority < sizeof(priorities) - 1 ? priorities[priority] : 'U';
}

void captureLog(int priority, char const* tag, char const* text) noexcept {
    if (getModConfig().Log.GetValue())
        buffer.appendLog(getPriorityChar(priority), tag ? tag : "", text ? text : "");
}

// On current Android, print/write functions can inline the dispatch and never
// enter __android_log_write_log_message. Capture their common destination,
// preserving Android/ART's existing logger and passing the message unchanged.
MAKE_HOOK_NO_CATCH(hook__android_log_logd_logger, (nullptr), void, struct __android_log_message const* message) {
    AndroidLogCrashGuard::Scope logging;
    if (message) captureLog(message->priority, message->tag, message->message);
    hook__android_log_logd_logger(message);
}

// Compatibility paths for Android versions without the common logd entry point.
MAKE_HOOK_NO_CATCH(hook__android_log_write_log_message, (nullptr), void, struct __android_log_message* message) {
    AndroidLogCrashGuard::Scope logging;
    if (message) captureLog(message->priority, message->tag, message->message);
    hook__android_log_write_log_message(message);
}

MAKE_HOOK_NO_CATCH(hook__android_log_write, (nullptr), int, int priority, const char* tag, const char* text) {
    AndroidLogCrashGuard::Scope logging;
    captureLog(priority, tag, text);
    return hook__android_log_write(priority, tag, text);
}

MAKE_HOOK_NO_CATCH(hook__android_log_buf_write, (nullptr), int, int bufferId, int priority, const char* tag, const char* text) {
    AndroidLogCrashGuard::Scope logging;
    captureLog(priority, tag, text);
    return hook__android_log_buf_write(bufferId, priority, tag, text);
}

// Hook 6 has no libunity-specific scanner. Search only readable executable
// ELF segments, retaining the unique-match checks without a fixed-size scan.
uintptr_t findUniquePatternInLibunity(bool& multiple, const char* pattern, const char* label) {
    struct Search { const char* pattern; const char* label; uintptr_t result; bool multiple; } search{pattern, label, 0, false};
    dl_iterate_phdr(+[](dl_phdr_info* info, size_t, void* opaque) {
        if (!std::string_view(info->dlpi_name).ends_with("/libunity.so")) return 0;
        auto& search = *static_cast<Search*>(opaque);
        for (size_t i = 0; i < info->dlpi_phnum; ++i) {
            auto const& segment = info->dlpi_phdr[i];
            if (segment.p_type != PT_LOAD || (segment.p_flags & (PF_R | PF_X)) != (PF_R | PF_X)) continue;
            bool duplicate = false;
            auto match = findUniquePattern(duplicate, info->dlpi_addr + segment.p_vaddr,
                search.pattern, search.label, segment.p_memsz);
            search.multiple |= duplicate || (match && search.result);
            if (match) search.result = match;
        }
        return 1;
    }, &search);
    multiple = search.multiple;
    return search.result;
}

bool changeFlag(uintptr_t addr) {
    // Change the MOVZ immediate from O_WRONLY to O_RDWR, preserving its register.
    auto instruction = reinterpret_cast<uint32_t*>(addr);
    if ((addr % alignof(uint32_t)) != 0 || (*instruction & ~0x1fu) != 0x52901820u) {
        LOG_ERROR("Unexpected tombstone open instruction at {}", reinterpret_cast<void*>(addr));
        return false;
    }
    auto pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0)
        return false;
    auto page = reinterpret_cast<void*>(addr - addr % static_cast<uintptr_t>(pageSize));
    if (mprotect(page, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOG_ERROR("Could not make tombstone flags writable: {}", errno);
        return false;
    }
    *instruction += 0x20;
    __builtin___clear_cache(reinterpret_cast<char*>(addr), reinterpret_cast<char*>(addr + sizeof(*instruction)));
    if (mprotect(page, pageSize, PROT_READ | PROT_EXEC) != 0) {
        LOG_ERROR("Could not restore tombstone page permissions: {}", errno);
        return false;
    }
    return true;
}

extern "C" __attribute__((visibility("default"))) void setup(CModInfo& info) {
    info.id = MOD_ID;
    info.version = VERSION;
    info.version_long = 0;
    modInfo.assign(info);
    getModConfig().Init(modInfo);
    // Migrate the default URL if it is still set to the old analyzer.
    if (getModConfig().Url.GetValue() == "https://analyzer.questmodding.com/api/upload") {
        getModConfig().Url.SetValue(getModConfig().Url.GetDefaultValue());
    }
}

extern "C" __attribute__((visibility("default"))) void load() {
    LOG_INFO("Starting {} installation...", MOD_ID);

    constexpr const auto logger = Paper::ConstLoggerContext(MOD_ID);
    // Initialize the native crash upload transport.
    auto curlResult = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curlResult != CURLE_OK) {
        LOG_ERROR("Could not initialize curl: {}", curl_easy_strerror(curlResult));
    }

    // Cache the running game's version before installing crash hooks, so
    // reporting never needs to call Unity APIs from the crash handler.
    il2cpp_functions::Init();
    auto gameVersion = UnityEngine::Application::get_version();
    if (gameVersion) GameVersion = std::string(gameVersion);

    auto buildId = getBuildId(modloader_get_libil2cpp_path());
    if(buildId.has_value())
        LibIl2CppBuildID = buildId.value();
    LOG_INFO("libil2cpp.so buildId: {}", LibIl2CppBuildID.c_str());

    uintptr_t libunity = baseAddr("libunity.so");
    LOG_INFO("libunity.so: {}", reinterpret_cast<void*>(libunity));
    //Change open() flags to O_RDWR, so that we can read the tombstone file descriptor again
    bool multiple = false;
    uintptr_t flags0 = findUniquePatternInLibunity(multiple, UnityCrashHandler::createFlags, "create_flags");
    if (!libunity || !flags0 || multiple) {
        LOG_ERROR("Unsupported Unity tombstone creation code; skipping CrashReporter hooks");
        return;
    }
    LOG_INFO("First flags: {}", reinterpret_cast<void*>(flags0));
    multiple = false;
    uintptr_t flags1 = findUniquePatternInLibunity(multiple, UnityCrashHandler::reopenFlags, "reopen_flags");
    if (!flags1 || multiple) {
        LOG_ERROR("Unsupported Unity tombstone reopen code; skipping CrashReporter hooks");
        return;
    }
    LOG_INFO("Second flags: {}", reinterpret_cast<void*>(flags1));

    multiple = false;
    uintptr_t engrave_tombstoneAddr = findUniquePatternInLibunity(multiple, UnityCrashHandler::engraveTombstone, "engrave_tombstone");
    if (!engrave_tombstoneAddr || multiple) {
        LOG_ERROR("Unsupported Unity crash handler; skipping CrashReporter hooks");
        return;
    }
    if (!CrashStack::initialize()) {
        LOG_ERROR("Could not allocate the crash handler stack; skipping CrashReporter hooks");
        return;
    }
    if (!changeFlag(flags0) || !changeFlag(flags1))
        return;
    LOG_INFO("engrave_tombstone: {}", reinterpret_cast<void*>(engrave_tombstoneAddr-libunity));
    INSTALL_HOOK_DIRECT(logger, engrave_tombstone, reinterpret_cast<void*>(engrave_tombstoneAddr));
    auto logdLogger = dlsym(RTLD_DEFAULT, "__android_log_logd_logger");
    auto writeLogMessage = dlsym(RTLD_DEFAULT, "__android_log_write_log_message");
    if (logdLogger) {
        INSTALL_HOOK_DIRECT(logger, hook__android_log_logd_logger, logdLogger);
    } else if (writeLogMessage) {
        INSTALL_HOOK_DIRECT(logger, hook__android_log_write_log_message, writeLogMessage);
    } else {
        INSTALL_HOOK_DIRECT(logger, hook__android_log_write, reinterpret_cast<void*>(__android_log_write));
        INSTALL_HOOK_DIRECT(logger, hook__android_log_buf_write, reinterpret_cast<void*>(__android_log_buf_write));
    }

    if (!AndroidLogCrashGuard::initialize())
        LOG_ERROR("Could not guard every Android logging crash signal");

    BSML::Init();

    if(getModConfig().UserId.GetValue().empty() || getModConfig().UserId.GetValue() == "Default") {
        getModConfig().UserId.SetValue(UnityEngine::SystemInfo::get_deviceUniqueIdentifier());
    }

    BSML::Register::RegisterSettingsMenu(MOD_ID, DidActivate, false);
    BSML::Register::RegisterMainMenu(MOD_ID, MOD_ID, "Configure crash reporting", DidActivate);
    LOG_INFO("Successfully installed {}!", MOD_ID);
}
