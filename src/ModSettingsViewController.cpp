#include "ModSettingsViewController.hpp"


#include "HMUI/Touchable.hpp"
#include "bsml/shared/BSML-Lite/Creation/Layout.hpp"
#include "ModConfig.hpp"

using namespace UnityEngine;
using namespace UnityEngine::UI;
using namespace HMUI;

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
        BSML::Lite::CreateUIButton(parent, "CRASH NOW!!!", []() {
            CRASH_UNLESS(0);
        });
    }
}