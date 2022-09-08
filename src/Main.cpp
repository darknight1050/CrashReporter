#include "beatsaber-hook/shared/utils/utils.h"
#include "beatsaber-hook/shared/utils/hooking.hpp"

#include "custom-types/shared/register.hpp"

#include "questui/shared/QuestUI.hpp"

#include "CustomLogger.hpp"
#include "ModConfig.hpp"
#include "ModSettingsViewController.hpp"

#include "libcurl/shared/curl.h"
#include "libcurl/shared/easy.h"

#include <sys/mman.h>
#include <sstream>
#include <iomanip>

#define PAGE_START(addr) (~(PAGE_SIZE - 1) & (addr))

#define TIMEOUT 5000
#define USER_AGENT (std::string("CrashReporter/") + VERSION + " (+https://github.com/darknight1050/CrashReporter)").c_str()


ModInfo modInfo;

Logger& getLogger() {
    static auto logger = new Logger(modInfo, LoggerOptions(false, true)); 
    return *logger; 
}

DEFINE_CONFIG(ModConfig);

extern "C" void setup(ModInfo& info) {
    modInfo.id = ID;
    modInfo.version = VERSION;
    info = modInfo;
    getModConfig().Init(modInfo);
}

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
    int size = 0;
    do {
        size = read(fd, buf, bufSize);
        data.append(buf, size);
    } while (size > 0);
    return data;
}

LogBuffer buffer(0x40000);

/*void _Z17engrave_tombstoneN7android4base14unique_fd_implINS0_13DefaultCloserEEEPvRKNSt6__ndk13mapIi1 0ThreadInfoNS5_4lessIiEENS5_9allocatorINS5_4pairIKiS7_EEEEEEimPNS6_Ii6FDInfoS9_NSA_INSB_ISC_SI_EEEEE EPNS5_12basic_stringIcNS5_11char_traitsIcEENSA_IcEEEE
               (undefined4 *param_1,undefined8 param_2,long param_3,int param_4,undefined8 param_5,
               undefined8 param_6,undefined8 param_7)*/
MAKE_HOOK_NO_CATCH(engrave_tombstone, 0x0, void, int* tombstone_fd, void* param_2, long param_3, int param_4, void* param_5, void* param_6, void* param_7) {
    engrave_tombstone(tombstone_fd, param_2, param_3, param_4, param_5, param_6, param_7);

    Logger::flushAll();

    if(!getModConfig().Enabled.GetValue())
        return;

    std::string url = getModConfig().Url.GetValue();
    const char* type = getModConfig().FullCrash.GetValue() ? "tombstone" : "crash";
    std::string userId = getModConfig().UserId.GetValue();
   
    LOG_INFO("Uploading %s to: %s", type, url.c_str());

    lseek(*tombstone_fd, 0, SEEK_SET);

    struct UploadData {
        std::string data = "";
        std::size_t offset = 0;
    };
    UploadData* uploadData = new UploadData();
    std::string crashId = "";
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

    uploadData->data = "{\"userId\": \"" + userId + "\", \"stacktrace\": \"";

    if(getModConfig().FullCrash.GetValue()) {
        uploadData->data += escape_json(readFD(*tombstone_fd));
    } else {
        uploadData->data += escape_json(std::string(*reinterpret_cast<char**>(param_2)));
    }

    if(getModConfig().Log.GetValue()) {
        uploadData->data += "\", \"log\":\"";
        std::string log = buffer.getData();
        auto firstLineEnd = log.find("\n");
        if(firstLineEnd != std::string::npos)
            log.erase(0, firstLineEnd + 1);
        uploadData->data += escape_json(log);
    }

    uploadData->data += "\"}";

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
                LOG_ERROR("Failed to allocate string of size: %lu", newLength);
                return std::size_t(0);
            }
            return newLength;
        });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &crashId);

    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    auto res = curl_easy_perform(curl);
    /* Check for errors */ 
    if (res == CURLE_OK) {
        LOG_INFO("Uploaded %s with crashId: %s and userId: %s", type, crashId.c_str(), userId.c_str());
    } else {
        LOG_ERROR("Uploading %s failed: %u: %s", type, res, curl_easy_strerror(res));
    }
    long httpCode(0);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);
    if(uploadData)
        delete uploadData;
}

MAKE_HOOK_NO_CATCH(hook__android_log_write, 0x0, int, int prio, const char* tag, const char* text) {
    if(getModConfig().Log.GetValue()) {
        auto begin = std::string(tag) + ": ";
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

void changeFlag(uintptr_t addr) {
	mprotect((void *) PAGE_START(addr), PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    *reinterpret_cast<char*>(addr) += 0x20;
	mprotect((void *) PAGE_START(addr), PAGE_SIZE * 2, PROT_READ |  PROT_EXEC);
}

extern "C" void load() {
    LOG_INFO("Starting %s installation...", ID);
    il2cpp_functions::Init();

    if(getModConfig().UserId.GetValue().empty()) {
        static function_ptr_t<StringW> getDeviceUniqueIdentifier = il2cpp_utils::resolve_icall<StringW>("UnityEngine.SystemInfo::GetDeviceUniqueIdentifier");
        getModConfig().UserId.SetValue(getDeviceUniqueIdentifier());
    }
    
    uintptr_t libunity = baseAddr("libunity.so");

    //Change open() flags to O_RDWR, so that we can read the tombstone file descriptor again
    auto flagsPattern = "?? 18 90 52";
    uintptr_t flags1 = findPattern(libunity, flagsPattern);
    uintptr_t flags2 = findPattern(flags1+4, flagsPattern);
    LOG_INFO("First flags: %p", reinterpret_cast<void*>(flags1-libunity));
    LOG_INFO("Second flags: %p", reinterpret_cast<void*>(flags2-libunity));
    changeFlag(flags1);
    changeFlag(flags2);

    uintptr_t engrave_tombstoneAddr = findPattern(libunity, "ff 43 04 d1 fc 63 0d a9 f7 5b 0e a9 f5 53 0f a9 f3 7b 10 a9 57 d0 3b d5 e8 16 40 f9 f4 03 02 aa");
    LOG_INFO("engrave_tombstone: %p", reinterpret_cast<void*>(engrave_tombstoneAddr-libunity));
    INSTALL_HOOK_DIRECT(getLogger(), engrave_tombstone, reinterpret_cast<void*>(engrave_tombstoneAddr));
    INSTALL_HOOK_DIRECT(getLogger(), hook__android_log_write, reinterpret_cast<void*>(__android_log_write));

    QuestUI::Register::RegisterModSettingsViewController(modInfo, DidActivate);
    LOG_INFO("Successfully installed %s!", ID);
}