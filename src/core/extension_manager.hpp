#pragma once

#include "logger.hpp"
#include "rift_sdk.h"

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace riftloader {

struct LoadedExtensionInfo {
    RiftExtHandle handle = RIFT_INVALID_HANDLE;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    std::string dll_path;
};

// SourceMod-style native DLL extension host with shared interface registry
// and named event bus. Calls `owner_cleanup` whenever an extension unloads.
class ExtensionManager {
public:
    using OwnerCleanupFn = std::function<void(RiftExtHandle)>;

    ExtensionManager(Logger& logger, const RiftLoaderAPI& api, OwnerCleanupFn owner_cleanup);
    ~ExtensionManager();

    ExtensionManager(const ExtensionManager&) = delete;
    ExtensionManager& operator=(const ExtensionManager&) = delete;

    void LoadDirectory(const std::string& dir_path,
                       const std::unordered_set<std::string>& disabled_names);
    bool LoadExtension(const std::string& dll_path, std::string& out_msg);
    bool UnloadByName(const std::string& name, std::string& out_msg);
    bool ReloadByName(const std::string& name, std::string& out_msg);
    void UnloadAll();

    std::vector<LoadedExtensionInfo> List() const;

    // Shared Interfaces (IShareSys)
    RiftResult RegisterInterface(RiftExtHandle owner, const std::string& name, uint32_t version, void* ptr);
    void* GetInterface(const std::string& name, uint32_t min_version) const;
    void RemoveInterfacesByOwner(RiftExtHandle owner);

    // Event Bus
    RiftEventSubHandle SubscribeEvent(RiftExtHandle owner, const std::string& event_name,
                                      RiftEventFn cb, void* user_data);
    void UnsubscribeEvent(RiftEventSubHandle sub);
    void RemoveEventsByOwner(RiftExtHandle owner);
    void EmitEvent(const std::string& event_name, const void* payload);

private:
    struct ExtEntry {
        LoadedExtensionInfo info;
        void* hmodule = nullptr; // HMODULE
        RiftExtUnloadFn unload_fn = nullptr;
    };

    struct SharedIface {
        RiftExtHandle owner = RIFT_INVALID_HANDLE;
        uint32_t version = 0;
        void* ptr = nullptr;
    };

    struct EventSub {
        RiftEventSubHandle handle = RIFT_INVALID_HANDLE;
        RiftExtHandle owner = RIFT_INVALID_HANDLE;
        std::string event_name;
        RiftEventFn cb = nullptr;
        void* user_data = nullptr;
    };

    void UnloadEntry(ExtEntry& e);

    Logger& logger_;
    const RiftLoaderAPI& api_;
    OwnerCleanupFn owner_cleanup_;

    mutable std::mutex mutex_;
    RiftExtHandle next_ext_handle_ = 1;
    std::vector<ExtEntry> extensions_;

    mutable std::mutex iface_mutex_;
    std::unordered_map<std::string, SharedIface> interfaces_;

    mutable std::mutex event_mutex_;
    RiftEventSubHandle next_sub_handle_ = 1;
    std::vector<EventSub> event_subs_;
};

} // namespace riftloader
