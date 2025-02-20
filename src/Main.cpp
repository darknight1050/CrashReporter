#include "beatsaber-hook/shared/utils/utils.h"
#include "beatsaber-hook/shared/utils/hooking.hpp"

#include "custom-types/shared/register.hpp"
#include "scotland2/shared/loader.hpp"

#include "CustomLogger.hpp"
#include "ModConfig.hpp"
#include "ModSettingsViewController.hpp"

#include "libcurl/shared/curl.h"
#include "libcurl/shared/easy.h"
#include "bsml/shared/BSML.hpp"
#include <sys/mman.h>
#include <sstream>
#include <iomanip>
#include <android/log.h>

#define PAGE_START(addr) (~(PAGE_SIZE - 1) & (addr))

#define TIMEOUT 3000
#define USER_AGENT (std::string("CrashReporter/") + VERSION + " (+https://github.com/darknight1050/CrashReporter)").c_str()

std::string LibIl2CppBuildID = "not_found";

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
        else if ((ch == '%') && IS_HEXDIG(s[i+0]) && IS_HEXDIG(s[i+1]))
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

class LogBuffer {

    char* buffer;
    size_t size;
    size_t index;
    bool wrapped;

public:
    LogBuffer(size_t size) {
        this->buffer = nullptr;
        this->size = size;
        this->index = 0;
        this->wrapped = false;
    }

    ~LogBuffer() {
        if (buffer)
            delete buffer;
    }

    void append(const std::string& text) {
        if(!buffer)
            buffer = new char[size];
        auto length = text.size();
        if (length <= size - index) {
            memcpy(buffer + index, text.data(), length);
            index += length;
            if (index >= size) {
                index = 0;
                wrapped = true;
            }
        }
        else {
            auto first = size - index;
            auto second = length - first;
            memcpy(buffer + index, text.data(), first);
            memcpy(buffer, text.data() + first, second);
            index = second;
            wrapped = true;
        }
    }

    const std::string getData() {
        if(!buffer)
            return "";
        std::string data;
        if(wrapped)
            data.append(buffer + index, size - index);
        data.append(buffer, index);
        return data;
    }

};

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

/*void engrave_tombstone(unique_fd_impl param_1,unique_fd_impl param_2,void *param_3,map *param_4, int param_5,ProcessInfo *param_6,OpenFilesList *param_7,basic_string *param_8)*/
MAKE_HOOK_NO_CATCH(engrave_tombstone, 0x0, void, int* tombstone_fd, int* param_2, void* param_3, void* param_4, int param_5, void* param_6, void* param_7, void* param_8) {
     engrave_tombstone(tombstone_fd, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    if(!getModConfig().Enabled.GetValue())
        return;
    std::string url = getModConfig().Url.GetValue();
    const char* type = getModConfig().FullCrash.GetValue() ? "tombstone" : "crash";
    std::string userId = getModConfig().UserId.GetValue();

    LOG_INFO("Uploading {} to: {}", type, url.c_str());
    Paper::ffi::paper2_wait_flush_timeout(50);

    struct UploadData {
        std::string data = "";
        std::size_t offset = 0;
    };
    UploadData* uploadData = new UploadData();
    std::string response = "";
    // Init curl
    auto* curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    // Set headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
    curl_easy_setopt(curl, CURLOPT_URL, query_encode(url).c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    // Don't wait forever, time out after TIMEOUT seconds.
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT);
    // Follow HTTP redirects if necessary.
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    uploadData->data = "{\"userId\": \"" + userId + "\", \"libIl2CppBuildID\": \"" + LibIl2CppBuildID + "\", \"stacktrace\": \"";

    if(getModConfig().FullCrash.GetValue()) {
        lseek(*tombstone_fd, 0, SEEK_SET);
        auto data = escape_json(readFD(*tombstone_fd));
        if(data.empty())
            data = escape_json("Fallback to normal crash:\n" + std::string(*reinterpret_cast<char**>(param_2)));
        uploadData->data += data;
    } else {
        uploadData->data += escape_json(std::string(*reinterpret_cast<char**>(param_2)));
    }
    uploadData->data += "\"";

    if(getModConfig().Log.GetValue()) {
        uploadData->data += ", \"log\":\"";
        std::string log = buffer.getData();
        auto firstLineEnd = log.find("\n");
        if(firstLineEnd != std::string::npos)
            log.erase(0, firstLineEnd + 1);
        uploadData->data += escape_json(log);
        uploadData->data += "\"";
    }

    uploadData->data += ", \"mods\": [";
    auto modResults = modloader_get_loaded();
    std::span<CModResult const> modResultsSpan(modResults.array, modResults.size);
    for (auto itr : modResultsSpan) {
        auto info = itr.info;
        uploadData->data += "{ \"name\":\"" + std::string(info.id) + "\", \"version\":\"" + info.version + "\", \"version_long\":" + std::to_string(info.version_long) + "},";
    }
    if(uploadData->data.ends_with(","))
        uploadData->data.erase(uploadData->data.end()-1);
    uploadData->data += "]";

    uploadData->data += "}";

    curl_easy_setopt(curl, CURLOPT_READFUNCTION,
        +[](char* buffer, std::size_t size, std::size_t nitems, UploadData* userdata) {
            std::size_t length = std::min(userdata->data.size() - userdata->offset, size * nitems);
            memcpy(buffer, userdata->data.data() + userdata->offset, length);
            userdata->offset += length;
            return length;
        });
    curl_easy_setopt(curl, CURLOPT_READDATA, uploadData);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, 
        +[](char* buffer, std::size_t size, std::size_t nitems, std::string* userdata) {
            std::size_t newLength = size * nitems;
            try {
                userdata->append(buffer, newLength);
            } catch(std::bad_alloc &e) {
                LOG_ERROR("Failed to allocate string of size: {}", newLength);
                return std::size_t(0);
            }
            return newLength;
        });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    auto res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        long httpCode(0);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        if(httpCode == 200) {
            LOG_INFO("Uploaded {} with crashId: {} and userId: {}", type, response.c_str(), userId.c_str());
        } else {
            LOG_ERROR("Uploading {} failed: {}: {}", type, httpCode, response.c_str());
        }
    } else {
        LOG_ERROR("Uploading {} failed: {}: {}", type, (long)res, curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
    delete uploadData;
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

MAKE_HOOK_NO_CATCH(hook__android_log_write, 0x0, int, int prio, const char* tag, const char* text) {
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

MAKE_HOOK_NO_CATCH(hook__android_log_buf_write, 0x0, int, int bufID, int prio, const char* tag, const char* text) {
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

MAKE_HOOK_NO_CATCH(hook__android_log_write_log_message, 0x0, void, struct __android_log_message* log_message) {
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

void changeFlag(uintptr_t addr) {
	mprotect((void *) PAGE_START(addr), PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    *reinterpret_cast<char*>(addr) += 0x20;
	mprotect((void *) PAGE_START(addr), PAGE_SIZE * 2, PROT_READ | PROT_EXEC);
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

    auto buildId = getBuildId(modloader_get_libil2cpp_path());
    if(buildId.has_value())
        LibIl2CppBuildID = buildId.value();
    LOG_INFO("libil2cpp.so buildId: {}", LibIl2CppBuildID.c_str());

    uintptr_t libunity = baseAddr("libunity.so");
    LOG_INFO("libunity.so: {}", reinterpret_cast<void*>(libunity));
    //Change open() flags to O_RDWR, so that we can read the tombstone file descriptor again
    auto flagsPattern = "40 f9 ?? 18 90 52";
    uintptr_t flags0 = findPattern(libunity, flagsPattern) + 2;
    uintptr_t flags1 = findPattern(flags0+4, flagsPattern) + 2;
    LOG_INFO("First flags: {}", reinterpret_cast<void*>(flags0-libunity));
    LOG_INFO("Second flags: {}", reinterpret_cast<void*>(flags1-libunity));
    changeFlag(flags0);
    changeFlag(flags1);

    uintptr_t engrave_tombstoneAddr = findPattern(libunity, "ff 83 04 d1 fd 6b 00 f9 fe 67 0e a9 f8 5f 0f a9 f6 57 10 a9 f4 4f 11 a9 58 d0 3b d5 08 17 40 f9 e1 03 1f 2a", 0x2000000);
    LOG_INFO("engrave_tombstone: {}", reinterpret_cast<void*>(engrave_tombstoneAddr-libunity));
    INSTALL_HOOK_DIRECT(logger, engrave_tombstone, reinterpret_cast<void*>(engrave_tombstoneAddr));
    void* __android_log_write_log_messageAddr = dlsym(RTLD_DEFAULT, "__android_log_write_log_message");
    LOG_INFO("__android_log_write_log_message: {}", __android_log_write_log_messageAddr);
    if(__android_log_write_log_messageAddr) {
        INSTALL_HOOK_DIRECT(logger, hook__android_log_write_log_message, __android_log_write_log_messageAddr);
    } else {
        INSTALL_HOOK_DIRECT(logger, hook__android_log_write, reinterpret_cast<void*>(__android_log_write));
        INSTALL_HOOK_DIRECT(logger, hook__android_log_buf_write, reinterpret_cast<void*>(__android_log_buf_write));
    }
    
    il2cpp_functions::Init();
    BSML::Init();

    if(getModConfig().UserId.GetValue().empty() || getModConfig().UserId.GetValue() == "Default") {
        static function_ptr_t<StringW> getDeviceUniqueIdentifier = il2cpp_utils::resolve_icall<StringW>("UnityEngine.SystemInfo::GetDeviceUniqueIdentifier");
        getModConfig().UserId.SetValue(getDeviceUniqueIdentifier());
    }

    BSML::Register::RegisterSettingsMenu(MOD_ID, DidActivate, false);
    LOG_INFO("Successfully installed {}!", MOD_ID);
}