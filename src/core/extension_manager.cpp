#include "extension_manager.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <filesystem>

namespace riftloader {

ExtensionManager::ExtensionManager(Logger& logger, const RiftLoaderAPI& api, OwnerCleanupFn owner_cleanup)
    : logger_(logger), api_(api), owner_cleanup_(std::move(owner_cleanup)) {}

ExtensionManager::~ExtensionManager() {
    UnloadAll();
}

void ExtensionManager::LoadDirectory(const std::string& dir_path,
                                     const std::unordered_set<std::string>& disabled_names) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(dir_path, ec)) {
        fs::create_directories(dir_path, ec);
        return;
    }

    std::vector<fs::path> dlls;
    for (const auto& entry : fs::directory_iterator(dir_path, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ".dll") {
            dlls.push_back(entry.path());
        }
    }
    std::sort(dlls.begin(), dlls.end());

    for (const auto& p : dlls) {
        std::string stem = p.stem().string();
        if (disabled_names.count(stem) || disabled_names.count(p.filename().string())) {
            logger_.Log(RIFT_LOG_INFO, "ext", "Skipping disabled extension: %s", p.filename().string().c_str());
            continue;
        }
        std::string msg;
        if (!LoadExtension(p.string(), msg)) {
            logger_.Log(RIFT_LOG_ERROR, "ext", "%s", msg.c_str());
        }
    }
}

bool ExtensionManager::LoadExtension(const std::string& dll_path, std::string& out_msg) {
    HMODULE mod = LoadLibraryA(dll_path.c_str());
    if (!mod) {
        DWORD err = GetLastError();
        out_msg = "LoadLibrary failed for '" + dll_path + "' (Win32 error " + std::to_string(err) + ")";
        return false;
    }

    auto query_fn = reinterpret_cast<RiftExtQueryFn>(GetProcAddress(mod, "RiftExt_Query"));
    auto load_fn  = reinterpret_cast<RiftExtLoadFn>(GetProcAddress(mod, "RiftExt_Load"));
    auto unload_fn = reinterpret_cast<RiftExtUnloadFn>(GetProcAddress(mod, "RiftExt_Unload"));

    if (!query_fn || !load_fn || !unload_fn) {
        FreeLibrary(mod);
        out_msg = "DLL '" + dll_path + "' is missing required RiftExt_Query/Load/Unload exports";
        return false;
    }

    RiftExtensionInfo info{};
    info.struct_size = sizeof(RiftExtensionInfo);
    info.api_version = RIFT_SDK_API_VERSION;

    if (!query_fn(&info)) {
        FreeLibrary(mod);
        out_msg = "RiftExt_Query returned false for '" + dll_path + "'";
        return false;
    }
    if (info.api_version != RIFT_SDK_API_VERSION) {
        FreeLibrary(mod);
        out_msg = "Extension '" + dll_path + "' API version mismatch (got " +
                  std::to_string(info.api_version) + ", expected " +
                  std::to_string(RIFT_SDK_API_VERSION) + ")";
        return false;
    }
    if (!info.name || info.name[0] == '\0') {
        FreeLibrary(mod);
        out_msg = "Extension '" + dll_path + "' returned empty name";
        return false;
    }

    RiftExtHandle handle = RIFT_INVALID_HANDLE;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& existing : extensions_) {
            if (existing.info.name == info.name) {
                FreeLibrary(mod);
                out_msg = "Extension '" + std::string(info.name) + "' is already loaded";
                return false;
            }
        }
        handle = next_ext_handle_++;
    }

    if (!load_fn(&api_, handle)) {
        // Clean up anything it may have partially registered before returning false.
        RemoveEventsByOwner(handle);
        RemoveInterfacesByOwner(handle);
        if (owner_cleanup_) owner_cleanup_(handle);
        FreeLibrary(mod);
        out_msg = "RiftExt_Load returned false for '" + std::string(info.name) + "'";
        return false;
    }

    ExtEntry entry;
    entry.info.handle = handle;
    entry.info.name = info.name;
    entry.info.version = info.version ? info.version : "0.0.0";
    entry.info.author = info.author ? info.author : "";
    entry.info.description = info.description ? info.description : "";
    entry.info.dll_path = dll_path;
    entry.hmodule = mod;
    entry.unload_fn = unload_fn;

    logger_.Log(RIFT_LOG_INFO, "ext", "Loaded extension '%s' v%s (%s)",
                entry.info.name.c_str(), entry.info.version.c_str(),
                entry.info.description.c_str());

    out_msg = "Loaded extension '" + entry.info.name + "' v" + entry.info.version;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        extensions_.push_back(std::move(entry));
    }
    return true;
}

void ExtensionManager::UnloadEntry(ExtEntry& e) {
    logger_.Log(RIFT_LOG_INFO, "ext", "Unloading extension '%s'", e.info.name.c_str());
    if (e.unload_fn) {
        e.unload_fn();
    }
    RemoveEventsByOwner(e.info.handle);
    RemoveInterfacesByOwner(e.info.handle);
    if (owner_cleanup_) {
        owner_cleanup_(e.info.handle);
    }
    if (e.hmodule) {
        FreeLibrary(static_cast<HMODULE>(e.hmodule));
        e.hmodule = nullptr;
    }
}

bool ExtensionManager::UnloadByName(const std::string& name, std::string& out_msg) {
    ExtEntry removed;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = extensions_.begin(); it != extensions_.end(); ++it) {
            if (it->info.name == name) {
                removed = std::move(*it);
                extensions_.erase(it);
                found = true;
                break;
            }
        }
    }
    if (!found) {
        out_msg = "Extension not loaded: " + name;
        return false;
    }
    UnloadEntry(removed);
    out_msg = "Unloaded extension '" + name + "'";
    return true;
}

bool ExtensionManager::ReloadByName(const std::string& name, std::string& out_msg) {
    std::string dll_path;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& e : extensions_) {
            if (e.info.name == name) {
                dll_path = e.info.dll_path;
                break;
            }
        }
    }
    if (dll_path.empty()) {
        out_msg = "Extension not loaded: " + name;
        return false;
    }
    std::string tmp;
    if (!UnloadByName(name, tmp)) {
        out_msg = tmp;
        return false;
    }
    return LoadExtension(dll_path, out_msg);
}

void ExtensionManager::UnloadAll() {
    std::vector<ExtEntry> copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        copy.swap(extensions_);
    }
    // Unload in reverse load order (LIFO).
    for (auto it = copy.rbegin(); it != copy.rend(); ++it) {
        UnloadEntry(*it);
    }
}

std::vector<LoadedExtensionInfo> ExtensionManager::List() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LoadedExtensionInfo> out;
    out.reserve(extensions_.size());
    for (const auto& e : extensions_) out.push_back(e.info);
    return out;
}

RiftResult ExtensionManager::RegisterInterface(RiftExtHandle owner, const std::string& name,
                                               uint32_t version, void* ptr) {
    if (name.empty() || !ptr) return RIFT_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(iface_mutex_);
    if (interfaces_.count(name)) return RIFT_ERR_ALREADY_EXISTS;
    interfaces_[name] = {owner, version, ptr};
    return RIFT_OK;
}

void* ExtensionManager::GetInterface(const std::string& name, uint32_t min_version) const {
    std::lock_guard<std::mutex> lock(iface_mutex_);
    auto it = interfaces_.find(name);
    if (it == interfaces_.end()) return nullptr;
    if (it->second.version < min_version) return nullptr;
    return it->second.ptr;
}

void ExtensionManager::RemoveInterfacesByOwner(RiftExtHandle owner) {
    if (owner == RIFT_INVALID_HANDLE) return;
    std::lock_guard<std::mutex> lock(iface_mutex_);
    for (auto it = interfaces_.begin(); it != interfaces_.end(); ) {
        if (it->second.owner == owner) it = interfaces_.erase(it);
        else ++it;
    }
}

RiftEventSubHandle ExtensionManager::SubscribeEvent(RiftExtHandle owner, const std::string& event_name,
                                                    RiftEventFn cb, void* user_data) {
    if (event_name.empty() || !cb) return RIFT_INVALID_HANDLE;
    std::lock_guard<std::mutex> lock(event_mutex_);
    RiftEventSubHandle h = next_sub_handle_++;
    event_subs_.push_back({h, owner, event_name, cb, user_data});
    return h;
}

void ExtensionManager::UnsubscribeEvent(RiftEventSubHandle sub) {
    if (sub == RIFT_INVALID_HANDLE) return;
    std::lock_guard<std::mutex> lock(event_mutex_);
    event_subs_.erase(
        std::remove_if(event_subs_.begin(), event_subs_.end(),
                       [sub](const EventSub& s) { return s.handle == sub; }),
        event_subs_.end());
}

void ExtensionManager::RemoveEventsByOwner(RiftExtHandle owner) {
    if (owner == RIFT_INVALID_HANDLE) return;
    std::lock_guard<std::mutex> lock(event_mutex_);
    event_subs_.erase(
        std::remove_if(event_subs_.begin(), event_subs_.end(),
                       [owner](const EventSub& s) { return s.owner == owner; }),
        event_subs_.end());
}

void ExtensionManager::EmitEvent(const std::string& event_name, const void* payload) {
    std::vector<EventSub> matching;
    {
        std::lock_guard<std::mutex> lock(event_mutex_);
        for (const auto& s : event_subs_) {
            if (s.event_name == event_name) matching.push_back(s);
        }
    }
    for (const auto& s : matching) {
        if (s.cb) s.cb(event_name.c_str(), payload, s.user_data);
    }
}

} // namespace riftloader
