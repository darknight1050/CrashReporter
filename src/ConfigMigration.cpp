#include "ConfigMigration.hpp"
#include "ModConfig.hpp"

void ConfigMigration::migrate() {
    // Migrate the default URL if it is still set to the old analyzer.
    if (getModConfig().Url.GetValue() == "https://analyzer.questmodding.com/api/upload") {
        getModConfig().Url.SetValue(getModConfig().Url.GetDefaultValue());
    }
}
