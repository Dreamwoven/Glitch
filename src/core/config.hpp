#pragma once

#include "rift_sdk.h"

#include <string>
#include <unordered_set>

namespace riftloader {

struct LoaderConfig {
    bool console = false;
    RiftLogLevel log_level = RIFT_LOG_INFO;
    std::string log_file = "glitch/glitch.log";
    std::string patches_dir = "glitch/patches";
    std::string extensions_dir = "glitch/extensions";
    std::unordered_set<std::string> disabled_patches;
    std::unordered_set<std::string> disabled_extensions;

    static LoaderConfig LoadOrDefault(const std::string& config_path, std::string* out_warning = nullptr);
    static bool WriteDefault(const std::string& config_path);
    bool Save(const std::string& config_path) const;
};

} // namespace riftloader
