#pragma once

#include "stub_alloc.hpp"
#include "logger.hpp"
#include "memory_patch.hpp"
#include "scanner.hpp"

#include <string>
#include <unordered_set>
#include <vector>

namespace riftloader {

struct ManifestPatchInfo {
    std::string name;
    std::string description;
    std::string author;
    std::string source_path;
    std::vector<std::string> required_manifests;
    size_t site_count = 0;
    bool enabled = false;
    std::string error;
};

// Loads, validates, applies, toggles, and hot-reloads declarative .rvt patch files.
class PatchManager {
public:
    PatchManager(Logger& logger, Scanner& scanner, MemoryPatcher& patcher, StubAllocator& stubs);
    ~PatchManager();

    void LoadDirectory(const std::string& dir_path, const std::unordered_set<std::string>& disabled_names);
    bool LoadManifestFile(const std::string& path, const std::unordered_set<std::string>& disabled_names);
    void UnloadAll();
    void ReloadAll(const std::string& dir_path, const std::unordered_set<std::string>& disabled_names);

    bool EnableByName(const std::string& name, std::string& out_msg);
    bool DisableByName(const std::string& name, std::string& out_msg);
    bool ToggleByName(const std::string& name, std::string& out_msg);

    std::vector<ManifestPatchInfo> List() const;

private:
    struct LoadedPatch {
        ManifestPatchInfo info;
        std::vector<RiftPatchHandle> handles;
        std::vector<void*> stubs;
    };

    LoadedPatch* FindByName(const std::string& name);
    const LoadedPatch* FindByName(const std::string& name) const;
    bool CheckDependenciesSatisfied(const std::vector<std::string>& reqs, std::string& out_missing) const;
    bool LoadParsedManifest(const std::string& path,
                            const struct RivetNode* root,
                            const std::unordered_set<std::string>& disabled_names,
                            const std::string& forced_error = {});
    bool ApplySite(LoadedPatch& lp, const struct RivetNode& site_node, bool enable_now, std::string& err);

    Logger& logger_;
    Scanner& scanner_;
    MemoryPatcher& patcher_;
    StubAllocator& stubs_;
    std::vector<LoadedPatch> loaded_;
};

} // namespace riftloader
