#pragma once
#include "config-utils/shared/config-utils.hpp"

DECLARE_CONFIG(ModConfig,

    CONFIG_VALUE(Enabled, bool, "Enabled", true);
    CONFIG_VALUE(Url, std::string, "Url", "http://192.168.1.104/upload");

    CONFIG_INIT_FUNCTION(
        CONFIG_INIT_VALUE(Enabled);
        CONFIG_INIT_VALUE(Url);
    )
)
