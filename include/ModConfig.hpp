#pragma once
#include "config-utils/shared/config-utils.hpp"

DECLARE_CONFIG(ModConfig,

    CONFIG_VALUE(Enabled, bool, "Enabled", true);
    CONFIG_VALUE(CrashOnly, bool, "CrashOnly", true);
    CONFIG_VALUE(UserId, std::string, "UserId", "");
    CONFIG_VALUE(Url, std::string, "Url", "https://analyzer.questmodding.com/api/upload");

    CONFIG_INIT_FUNCTION(
        CONFIG_INIT_VALUE(Enabled);
        CONFIG_INIT_VALUE(CrashOnly);
        CONFIG_INIT_VALUE(UserId);
        CONFIG_INIT_VALUE(Url);
    )
)
