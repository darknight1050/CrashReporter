#include "beatsaber-hook/shared/utils.hpp"
#include "beatsaber-hook/shared/hooking.hpp"
#include "beatsaber-hook/shared/binary.hpp"

#include "scotland2/shared/loader.hpp"

#include "CustomLogger.hpp"
#include "ModConfig.hpp"
#include "ModSettingsViewController.hpp"
#include "UnityCrashHandlerPatterns.hpp"
#include "UnityEngine/SystemInfo.hpp"
#include "UnityEngine/Application.hpp"
#include "LogBuffer.hpp"
#include "Gzip.hpp"

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
        auto log = buffer.getData();
        auto firstLineEnd = log.find('\n');
        if (firstLineEnd != std::string::npos) log.erase(0, firstLineEnd + 1);
        data += ",\"log\":\"" + escape_json(log) + "\"";
    }
    data += ",\"mods\":[";
    auto mods = modloader_get_loaded();
    auto releaseMods = i2c::on_scope_exit([&] { modloader_free_results(&mods); });
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

MAKE_HOOK(engrave_tombstone, (nullptr), void, int* tombstone_fd, int* param_2, void* param_3, void* param_4, int param_5, void* param_6, void* param_7, void* param_8) {
    engrave_tombstone(tombstone_fd, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
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

std::string getPrioString(android_LogPriority prio) {
    switch(prio) {
        case ANDROID_LOG_UNKNOWN:
        return "U";
        case ANDROID_LOG_DEFAULT:
        return " ";
        case ANDROID_LOG_VERBOSE:
        return "V";
        case ANDROID_LOG_DEBUG:
        return "D";
        case ANDROID_LOG_INFO:
        return "I";
        case ANDROID_LOG_WARN:
        return "W";
        case ANDROID_LOG_ERROR:
        return "E";
        case ANDROID_LOG_FATAL:
        return "F";
        case ANDROID_LOG_SILENT:
        return "S";
    }
    return "U";
}

MAKE_HOOK(hook__android_log_write, (nullptr), int, int prio, const char* tag, const char* text) {
    if(getModConfig().Log.GetValue()) {
        if(!tag)
            tag = "";
        if(!text)
            text = "";
        auto begin = getPrioString((android_LogPriority)prio) + " " + std::string(tag) + ": ";
        auto message = begin + std::string(text);
        size_t start_pos = 0;
        while((start_pos = message.find("\n", start_pos)) != std::string::npos) {
            if(start_pos != message.length()-1)
                message.insert(start_pos + 1, begin);
            start_pos += begin.length() + 1;
        }
        if(!message.ends_with("\n"))
            message += "\n";
        buffer.append(message);
    }
    return hook__android_log_write(prio, tag, text);
}

MAKE_HOOK(hook__android_log_buf_write, (nullptr), int, int bufID, int prio, const char* tag, const char* text) {
    if(getModConfig().Log.GetValue()) {
        if(!tag)
            tag = "";
        if(!text)
            text = "";
        auto begin = getPrioString((android_LogPriority)prio) + " " + std::string(tag) + ": ";
        auto message = begin + std::string(text);
        size_t start_pos = 0;
        while((start_pos = message.find("\n", start_pos)) != std::string::npos) {
            if(start_pos != message.length()-1)
                message.insert(start_pos + 1, begin);
            start_pos += begin.length() + 1;
        }
        if(!message.ends_with("\n"))
            message += "\n";
        buffer.append(message);
    }
    return hook__android_log_buf_write(bufID, prio, tag, text);
}

MAKE_HOOK(hook__android_log_write_log_message, (nullptr), void, struct __android_log_message* log_message) {
    if(log_message && getModConfig().Log.GetValue()) {
        if(!log_message->tag)
            log_message->tag = "";
        if(!log_message->message)
            log_message->message = "";
        auto begin = getPrioString((android_LogPriority)log_message->priority) + " " + std::string(log_message->tag) + ": ";
        auto message = begin + std::string(log_message->message);
        size_t start_pos = 0;
        while((start_pos = message.find("\n", start_pos)) != std::string::npos) {
            if(start_pos != message.length()-1)
                message.insert(start_pos + 1, begin);
            start_pos += begin.length() + 1;
        }
        if(!message.ends_with("\n"))
            message += "\n";
        buffer.append(message);
    }
    hook__android_log_write_log_message(log_message);
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
    i2c::functions::initialize();
    auto gameVersion = UnityEngine::Application::get_version();
    if (gameVersion) GameVersion = std::string(gameVersion);

    auto buildId = i2c::binary::get_build_id(modloader_get_libil2cpp_path());
    if(buildId.has_value())
        LibIl2CppBuildID = buildId.value();
    LOG_INFO("libil2cpp.so buildId: {}", LibIl2CppBuildID.c_str());

    uintptr_t libunity = i2c::binary::base_addr("libunity.so");
    LOG_INFO("libunity.so: {}", reinterpret_cast<void*>(libunity));
    //Change open() flags to O_RDWR, so that we can read the tombstone file descriptor again
    bool multiple = false;
    uintptr_t flags0 = i2c::binary::libunity_unique_pattern(multiple, UnityCrashHandler::createFlags, "create_flags");
    if (!libunity || !flags0 || multiple) {
        LOG_ERROR("Unsupported Unity tombstone creation code; skipping CrashReporter hooks");
        return;
    }
    LOG_INFO("First flags: {}", reinterpret_cast<void*>(flags0));
    multiple = false;
    uintptr_t flags1 = i2c::binary::libunity_unique_pattern(multiple, UnityCrashHandler::reopenFlags, "reopen_flags");
    if (!flags1 || multiple) {
        LOG_ERROR("Unsupported Unity tombstone reopen code; skipping CrashReporter hooks");
        return;
    }
    LOG_INFO("Second flags: {}", reinterpret_cast<void*>(flags1));

    multiple = false;
    uintptr_t engrave_tombstoneAddr = i2c::binary::libunity_unique_pattern(multiple, UnityCrashHandler::engraveTombstone, "engrave_tombstone");
    if (!engrave_tombstoneAddr || multiple) {
        LOG_ERROR("Unsupported Unity crash handler; skipping CrashReporter hooks");
        return;
    }
    if (!changeFlag(flags0) || !changeFlag(flags1))
        return;
    LOG_INFO("engrave_tombstone: {}", reinterpret_cast<void*>(engrave_tombstoneAddr-libunity));
    INSTALL_HOOK(logger, engrave_tombstone, reinterpret_cast<void*>(engrave_tombstoneAddr));
    void* __android_log_write_log_messageAddr = dlsym(RTLD_DEFAULT, "__android_log_write_log_message");
    LOG_INFO("__android_log_write_log_message: {}", __android_log_write_log_messageAddr);
    if(__android_log_write_log_messageAddr) {
        INSTALL_HOOK(logger, hook__android_log_write_log_message, __android_log_write_log_messageAddr);
    } else {
        INSTALL_HOOK(logger, hook__android_log_write, reinterpret_cast<void*>(__android_log_write));
        INSTALL_HOOK(logger, hook__android_log_buf_write, reinterpret_cast<void*>(__android_log_buf_write));
    }

    BSML::Init();

    if(getModConfig().UserId.GetValue().empty() || getModConfig().UserId.GetValue() == "Default") {
        getModConfig().UserId.SetValue(UnityEngine::SystemInfo::get_deviceUniqueIdentifier());
    }

    BSML::Register::RegisterSettingsMenu(MOD_ID, DidActivate, false);
    LOG_INFO("Successfully installed {}!", MOD_ID);
}
