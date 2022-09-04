#include "beatsaber-hook/shared/utils/utils.h"
#include "beatsaber-hook/shared/utils/hooking.hpp"

#include "custom-types/shared/register.hpp"

#include "questui/shared/QuestUI.hpp"

#include "CustomLogger.hpp"
#include "ModConfig.hpp"

#include "libcurl/shared/curl.h"
#include "libcurl/shared/easy.h"
#include <sys/mman.h>

#define PAGE_START(addr) (~(PAGE_SIZE - 1) & (addr))

#define TIMEOUT 5000
#define USER_AGENT (std::string("CrashReporter/") + VERSION + " (+https://github.com/darknight1050/CrashReporter)").c_str()

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


/*void _Z17engrave_tombstoneN7android4base14unique_fd_implINS0_13DefaultCloserEEEPvRKNSt6__ndk13mapIi1 0ThreadInfoNS5_4lessIiEENS5_9allocatorINS5_4pairIKiS7_EEEEEEimPNS6_Ii6FDInfoS9_NSA_INSB_ISC_SI_EEEEE EPNS5_12basic_stringIcNS5_11char_traitsIcEENSA_IcEEEE
               (undefined4 *param_1,undefined8 param_2,long param_3,int param_4,undefined8 param_5,
               undefined8 param_6,undefined8 param_7)*/
MAKE_HOOK_NO_CATCH(engrave_tombstone_impl, 0x0, void, int* tombstone_fd, void* param_2, long param_3, int param_4, void* param_5, void* param_6, void* param_7) {
    engrave_tombstone_impl(tombstone_fd, param_2, param_3, param_4, param_5, param_6, param_7);

    Logger::flushAll();

    if(!getModConfig().Enabled.GetValue())
        return;

    std::string url = getModConfig().Url.GetValue();
    const char* type = getModConfig().CrashOnly.GetValue() ? "crash" : "tombstone";
   
    LOG_INFO("Uploading %s to: %s", type, url.c_str());

    lseek(*tombstone_fd, 0, SEEK_SET);

    struct ReadData {
        std::string data;
        std::size_t offset;
    };
    ReadData* readData = 0;
    // Init curl
    auto* curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    // Set headers
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
    curl_easy_setopt(curl, CURLOPT_URL, query_encode(url).c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    // Don't wait forever, time out after TIMEOUT seconds.
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT);
    // Follow HTTP redirects if necessary.
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    if(getModConfig().CrashOnly.GetValue()) {
        readData = new ReadData { std::string(*reinterpret_cast<char**>(param_2)), 0 };
        curl_easy_setopt(curl, CURLOPT_READFUNCTION,
            +[](char* buffer, std::size_t size, std::size_t nitems, ReadData* userdata) {
                std::size_t length = std::min(userdata->data.size() - userdata->offset, size * nitems);
                memcpy(buffer, userdata->data.data() + userdata->offset, length);
                userdata->offset += length;
                return length;
            });
        curl_easy_setopt(curl, CURLOPT_READDATA, readData);
    } else {
        curl_easy_setopt(curl, CURLOPT_READFUNCTION,
            +[](char* buffer, std::size_t size, std::size_t nitems, int* userdata) {
                return read(*userdata, buffer, size * nitems);
            });
        curl_easy_setopt(curl, CURLOPT_READDATA, tombstone_fd);
    }

    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    auto res = curl_easy_perform(curl);
    /* Check for errors */ 
    if (res == CURLE_OK) {
        LOG_INFO("Uploaded %s!", type);
    } else {
        LOG_ERROR("Uploading %s failed: %u: %s", type, res, curl_easy_strerror(res));
    }
    long httpCode(0);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);
    if(readData)
        delete readData;
}

void changeFlag(uintptr_t addr) {
	mprotect((void *) PAGE_START(addr), PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    *reinterpret_cast<char*>(addr) += 0x20;
	mprotect((void *) PAGE_START(addr), PAGE_SIZE * 2, PROT_READ |  PROT_EXEC);
}

extern "C" void load() {
    LOG_INFO("Starting %s installation...", ID);
    il2cpp_functions::Init();
    QuestUI::Init();
    custom_types::Register::AutoRegister();
    
    uintptr_t libunity = baseAddr("libunity.so");

    //Change open() flags to O_RDWR
    auto flagsPattern = "?? 18 90 52";
    uintptr_t flags1 = findPattern(libunity, flagsPattern);
    uintptr_t flags2 = findPattern(flags1+4, flagsPattern);
    LOG_INFO("First flags: %p", reinterpret_cast<void*>(flags1-libunity));
    LOG_INFO("Second flags: %p", reinterpret_cast<void*>(flags2-libunity));
    changeFlag(flags1);
    changeFlag(flags2);

    uintptr_t engrave_tombstone_implAddr = findPattern(libunity, "ff 43 04 d1 fc 63 0d a9 f7 5b 0e a9 f5 53 0f a9 f3 7b 10 a9 57 d0 3b d5 e8 16 40 f9 f4 03 02 aa");
    LOG_INFO("engrave_tombsstone_impl: %p", reinterpret_cast<void*>(engrave_tombstone_implAddr-libunity));
    INSTALL_HOOK_DIRECT(getLogger(), engrave_tombstone_impl, reinterpret_cast<void*>(engrave_tombstone_implAddr));

    LOG_INFO("Successfully installed %s!", ID);
}