#include "config.hpp"
#include "logger.hpp"
#include "rivet_parser.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <vector>

namespace riftloader {

namespace {

std::string EscapeRivetString(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '"') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

const char* LogLevelToString(RiftLogLevel lvl) {
    switch (lvl) {
        case RIFT_LOG_TRACE: return "trace";
        case RIFT_LOG_DEBUG: return "debug";
        case RIFT_LOG_INFO:  return "info";
        case RIFT_LOG_WARN:  return "warn";
        case RIFT_LOG_ERROR: return "error";
        default:             return "info";
    }
}

} // namespace

LoaderConfig LoaderConfig::LoadOrDefault(const std::string& config_path, std::string* out_warning) {
    LoaderConfig cfg;
    if (!std::filesystem::exists(config_path)) {
        WriteDefault(config_path);
        return cfg;
    }

    auto parsed = RivetParser::ParseFile(config_path);
    if (!parsed.Ok()) {
        if (out_warning) {
            *out_warning = "Failed to parse config '" + config_path + "' (line " +
                           std::to_string(parsed.error_line) + "): " + parsed.error +
                           " - using defaults";
        }
        return cfg;
    }

    const RivetNode* r = parsed.root.get();
    cfg.console = r->GetBool("console", cfg.console);
    cfg.log_level = Logger::ParseLevel(r->GetString("log_level", "info"), cfg.log_level);
    cfg.log_file = r->GetString("log_file", cfg.log_file);
    cfg.patches_dir = r->GetString("patches_dir", cfg.patches_dir);
    cfg.extensions_dir = r->GetString("extensions_dir", cfg.extensions_dir);

    if (const RivetNode* dp = r->Get("disabled_patches")) {
        for (const auto& child : dp->ordered_children) {
            if (!child->raw_value.empty()) cfg.disabled_patches.insert(child->raw_value);
        }
    }
    if (const RivetNode* de = r->Get("disabled_extensions")) {
        for (const auto& child : de->ordered_children) {
            if (!child->raw_value.empty()) cfg.disabled_extensions.insert(child->raw_value);
        }
    }
    return cfg;
}

bool LoaderConfig::WriteDefault(const std::string& config_path) {
    LoaderConfig def;
    return def.Save(config_path);
}

bool LoaderConfig::Save(const std::string& config_path) const {
    try {
        std::filesystem::path p(config_path);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
    } catch (...) {
        return false;
    }

    std::vector<std::string> dp(disabled_patches.begin(), disabled_patches.end());
    std::sort(dp.begin(), dp.end());
    std::vector<std::string> de(disabled_extensions.begin(), disabled_extensions.end());
    std::sort(de.begin(), de.end());

    std::ofstream f(config_path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << "// Glitch configuration (Rivet notation)\n"
      << "console." << (console ? "true" : "false") << "\n"
      << "log_level.\"" << LogLevelToString(log_level) << "\"\n"
      << "log_file.\"" << EscapeRivetString(log_file) << "\"\n"
      << "patches_dir.\"" << EscapeRivetString(patches_dir) << "\"\n"
      << "extensions_dir.\"" << EscapeRivetString(extensions_dir) << "\"\n"
      << "disabled_patches.arr;\n";
    for (const auto& name : dp) {
        f << "\t.\"" << EscapeRivetString(name) << "\"\n";
    }
    f << "disabled_extensions.arr;\n";
    for (const auto& name : de) {
        f << "\t.\"" << EscapeRivetString(name) << "\"\n";
    }
    return f.good();
}

} // namespace riftloader
