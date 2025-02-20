#pragma once
#include "config-utils/shared/config-utils.hpp"

DECLARE_CONFIG(ModConfig) {

    CONFIG_VALUE(Enabled, bool, "Enabled", true);
    CONFIG_VALUE(FullCrash, bool, "FullCrash", false, "Upload tombstone or only backtrace");
    CONFIG_VALUE(Log, bool, "Log", false, "Upload last log lines");
    CONFIG_VALUE(UserId, std::string, "UserId", "Default");
    CONFIG_VALUE(Url, std::string, "Url", "https://analyzer.questmodding.com/api/upload");

};
