#include "ModSettingsViewController.hpp"


#include "HMUI/Touchable.hpp"
#include "bsml/shared/BSML-Lite/Creation/Layout.hpp"
#include "ModConfig.hpp"
#include "CustomLogger.hpp"
#include "beatsaber-hook/shared/utils.hpp"
#include "UnityEngine/Application.hpp"
#include "libcurl/shared/curl.h"
#include <memory>
#include <atomic>
#include <thread>

using namespace UnityEngine;
using namespace UnityEngine::UI;
using namespace HMUI;

namespace {
void requestCrash(bool workerThread) {
    static std::atomic_flag requested{};
    if (requested.test_and_set()) return;

    auto crash = [] {
        CRASH_UNLESS(false);
    };
    if (workerThread) std::thread(crash).detach();
    else crash();
}
}

void DidActivate(ViewController* self, bool firstActivation, bool addedToHierarchy, bool screenSystemEnabling) {
    if(firstActivation) {
        self->get_gameObject()->AddComponent<Touchable*>();

        GameObject* container = BSML::Lite::CreateScrollableSettingsContainer(self->get_transform());
        Transform* parent = container->get_transform();

        auto layout = BSML::Lite::CreateHorizontalLayoutGroup(parent);
        layout->GetComponent<LayoutElement*>()->set_preferredWidth(90.0f);
        layout->set_childControlWidth(true);
        auto layoutParent = layout->get_transform();
        
        AddConfigValueToggle(parent, getModConfig().Enabled);
        AddConfigValueToggle(parent, getModConfig().FullCrash);
        AddConfigValueToggle(parent, getModConfig().Log);
        AddConfigValueInputString(parent, getModConfig().UserId);
        BSML::Lite::CreateUIButton(parent, "View My Crash Reports", []() {
            auto userId = getModConfig().UserId.GetValue();
            std::unique_ptr<char, decltype(&curl_free)> encoded(
                curl_easy_escape(nullptr, userId.c_str(), 0), curl_free);
            if (!encoded) {
                LOG_ERROR("Could not encode UserId for the crash reports page");
                return;
            }
            auto url = getModConfig().Url.GetValue();
            constexpr std::string_view uploadPath = "/api/upload";
            if (url.ends_with(uploadPath)) {
                url.resize(url.size() - uploadPath.size());
            } else {
                auto path = url.find('/', url.find("://") + 3);
                if (path != std::string::npos) url.resize(path);
            }
            UnityEngine::Application::OpenURL(url + "/crashes?userId=" + encoded.get());
        });
        BSML::Lite::CreateUIButton(parent, "CRASH (Worker Thread)", [] { requestCrash(true); });
        BSML::Lite::CreateUIButton(parent, "CRASH (Main Thread)", [] { requestCrash(false); });
    }
}
