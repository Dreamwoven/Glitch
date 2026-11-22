#include "loader_main.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <sstream>

namespace riftloader {

namespace {

LoaderRuntime* g_active_runtime = nullptr;

// Static C-ABI trampolines dispatching to g_active_runtime.
void Api_Log(RiftLogLevel level, const char* tag, const char* fmt, ...) {
    if (!g_active_runtime) return;
    va_list args;
    va_start(args, fmt);
    g_active_runtime->Log().LogV(level, tag, fmt, args);
    va_end(args);
}

void Api_ConsolePrint(const char* text) {
    if (!g_active_runtime || !text) return;
    g_active_runtime->Log().WriteRawConsole(text);
}

uintptr_t Api_GetGameBase(void) {
    return g_active_runtime ? g_active_runtime->GetScanner().ModuleBase() : 0;
}

size_t Api_GetGameImageSize(void) {
    return g_active_runtime ? g_active_runtime->GetScanner().ImageSize() : 0;
}

uintptr_t Api_VaToLive(uint64_t static_va) {
    return g_active_runtime ? g_active_runtime->GetScanner().VaToLive(static_va) : 0;
}

uintptr_t Api_RvaToLive(uint32_t rva) {
    return g_active_runtime ? g_active_runtime->GetScanner().RvaToLive(rva) : 0;
}

uint64_t Api_LiveToVa(uintptr_t live_addr) {
    return g_active_runtime ? g_active_runtime->GetScanner().LiveToVa(live_addr) : 0;
}

RiftResult Api_ScanPattern(const char* pattern, uintptr_t* out_addr) {
    if (!g_active_runtime || !pattern || !out_addr) return RIFT_ERR_INVALID_ARG;
    return g_active_runtime->GetScanner().FindPattern(pattern, *out_addr);
}

RiftResult Api_ScanSection(const char* section_name, const char* pattern, uintptr_t* out_addr) {
    if (!g_active_runtime || !section_name || !pattern || !out_addr) return RIFT_ERR_INVALID_ARG;
    return g_active_runtime->GetScanner().FindPatternInSection(section_name, pattern, *out_addr);
}

RiftResult Api_PatchCreate(RiftExtHandle owner, const char* id, uintptr_t live_addr,
                           const uint8_t* expected_orig, const uint8_t* patch_bytes,
                           size_t length, bool enable_now, RiftPatchHandle* out_handle) {
    if (!g_active_runtime) return RIFT_ERR_INTERNAL;
    return g_active_runtime->Patcher().Create(
        owner, id ? id : "", live_addr, expected_orig, patch_bytes, length, enable_now, out_handle);
}

RiftResult Api_PatchEnable(RiftPatchHandle handle) {
    return g_active_runtime ? g_active_runtime->Patcher().Enable(handle) : RIFT_ERR_INTERNAL;
}

RiftResult Api_PatchDisable(RiftPatchHandle handle) {
    return g_active_runtime ? g_active_runtime->Patcher().Disable(handle) : RIFT_ERR_INTERNAL;
}

RiftResult Api_PatchRemove(RiftPatchHandle handle) {
    return g_active_runtime ? g_active_runtime->Patcher().Remove(handle) : RIFT_ERR_INTERNAL;
}

RiftResult Api_HookCreate(RiftExtHandle owner, const char* id, void* target, void* detour,
                          void** out_original, bool enable_now, RiftHookHandle* out_handle) {
    if (!g_active_runtime) return RIFT_ERR_INTERNAL;
    return g_active_runtime->Hooks().Create(
        owner, id ? id : "", target, detour, out_original, enable_now, out_handle);
}

RiftResult Api_HookEnable(RiftHookHandle handle) {
    return g_active_runtime ? g_active_runtime->Hooks().Enable(handle) : RIFT_ERR_INTERNAL;
}

RiftResult Api_HookDisable(RiftHookHandle handle) {
    return g_active_runtime ? g_active_runtime->Hooks().Disable(handle) : RIFT_ERR_INTERNAL;
}

RiftResult Api_HookRemove(RiftHookHandle handle) {
    return g_active_runtime ? g_active_runtime->Hooks().Remove(handle) : RIFT_ERR_INTERNAL;
}

void* Api_StubAlloc(RiftExtHandle owner, size_t size) {
    if (!g_active_runtime) return nullptr;
    return g_active_runtime->Stubs().Alloc(g_active_runtime->GetScanner().ModuleBase(), size, owner);
}

void Api_StubFree(void* ptr) {
    if (g_active_runtime) g_active_runtime->Stubs().Free(ptr);
}

RiftResult Api_RegisterInterface(RiftExtHandle owner, const char* name, uint32_t version, void* ptr) {
    if (!g_active_runtime || !name) return RIFT_ERR_INVALID_ARG;
    return g_active_runtime->Extensions().RegisterInterface(owner, name, version, ptr);
}

void* Api_GetInterface(const char* name, uint32_t min_version) {
    if (!g_active_runtime || !name) return nullptr;
    return g_active_runtime->Extensions().GetInterface(name, min_version);
}

RiftEventSubHandle Api_SubscribeEvent(RiftExtHandle owner, const char* event_name,
                                      RiftEventFn cb, void* user_data) {
    if (!g_active_runtime || !event_name) return RIFT_INVALID_HANDLE;
    return g_active_runtime->Extensions().SubscribeEvent(owner, event_name, cb, user_data);
}

void Api_UnsubscribeEvent(RiftEventSubHandle sub) {
    if (g_active_runtime) g_active_runtime->Extensions().UnsubscribeEvent(sub);
}

void Api_EmitEvent(const char* event_name, const void* payload) {
    if (g_active_runtime && event_name) {
        g_active_runtime->Extensions().EmitEvent(event_name, payload);
    }
}

RiftResult Api_RegisterCommand(RiftExtHandle owner, const char* name, const char* help,
                               RiftCommandFn cb, void* user_data) {
    if (!g_active_runtime || !name) return RIFT_ERR_INVALID_ARG;
    return g_active_runtime->GetConsole().RegisterCommand(owner, name, help ? help : "", cb, user_data);
}

void Api_UnregisterCommand(const char* name) {
    if (g_active_runtime && name) g_active_runtime->GetConsole().UnregisterCommand(name);
}

std::string g_game_dir_storage;
std::string g_loader_dir_storage;

const char* Api_GetGameDir(void) { return g_game_dir_storage.c_str(); }
const char* Api_GetLoaderDir(void) { return g_loader_dir_storage.c_str(); }

std::string GetExeDirectory() {
    char buf[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return ".";
    return std::filesystem::path(buf).parent_path().string();
}

} // namespace

LoaderRuntime::~LoaderRuntime() {
    Shutdown();
}

std::string LoaderRuntime::ResolvePath(const std::string& rel_or_abs) const {
    std::filesystem::path p(rel_or_abs);
    if (p.is_absolute()) return p.string();
    return (std::filesystem::path(game_dir_) / p).string();
}

void LoaderRuntime::BuildApiTable() {
    api_ = {};
    api_.struct_size = sizeof(RiftLoaderAPI);
    api_.api_version = RIFT_SDK_API_VERSION;

    api_.Log = Api_Log;
    api_.ConsolePrint = Api_ConsolePrint;
    api_.GetGameBase = Api_GetGameBase;
    api_.GetGameImageSize = Api_GetGameImageSize;
    api_.VaToLive = Api_VaToLive;
    api_.RvaToLive = Api_RvaToLive;
    api_.LiveToVa = Api_LiveToVa;
    api_.ScanPattern = Api_ScanPattern;
    api_.ScanSection = Api_ScanSection;
    api_.PatchCreate = Api_PatchCreate;
    api_.PatchEnable = Api_PatchEnable;
    api_.PatchDisable = Api_PatchDisable;
    api_.PatchRemove = Api_PatchRemove;
    api_.HookCreate = Api_HookCreate;
    api_.HookEnable = Api_HookEnable;
    api_.HookDisable = Api_HookDisable;
    api_.HookRemove = Api_HookRemove;
    api_.StubAlloc = Api_StubAlloc;
    api_.StubFree = Api_StubFree;
    api_.RegisterInterface = Api_RegisterInterface;
    api_.GetInterface = Api_GetInterface;
    api_.SubscribeEvent = Api_SubscribeEvent;
    api_.UnsubscribeEvent = Api_UnsubscribeEvent;
    api_.EmitEvent = Api_EmitEvent;
    api_.RegisterCommand = Api_RegisterCommand;
    api_.UnregisterCommand = Api_UnregisterCommand;
    api_.GetGameDir = Api_GetGameDir;
    api_.GetLoaderDir = Api_GetLoaderDir;
}

void LoaderRuntime::CleanupExtensionResources(RiftExtHandle owner) {
    if (console_) console_->UnregisterByOwner(owner);
    if (hooks_) hooks_->RemoveByOwner(owner);
    patcher_.RemoveByOwner(owner);
    stubs_.FreeByOwner(owner);
}

bool LoaderRuntime::Initialize(const std::string& game_dir, uintptr_t module_base, bool allow_console) {
    if (initialized_) return true;

    game_dir_ = game_dir;
    loader_dir_ = (std::filesystem::path(game_dir_) / "glitch").string();
    config_path_ = (std::filesystem::path(loader_dir_) / "config.rvt").string();
    g_game_dir_storage = game_dir_;
    g_loader_dir_storage = loader_dir_;

    std::error_code ec;
    std::filesystem::create_directories(loader_dir_, ec);

    std::string cfg_warn;
    config_ = LoaderConfig::LoadOrDefault(config_path_, &cfg_warn);

    logger_.SetMinLevel(config_.log_level);
    logger_.OpenFile(ResolvePath(config_.log_file));

    console_ = std::make_unique<Console>(logger_);
    if (allow_console && config_.console) {
        console_->StartWindow("Glitch Console");
    }

    if (!cfg_warn.empty()) {
        logger_.Log(RIFT_LOG_WARN, "config", "%s", cfg_warn.c_str());
    }

    scanner_ = std::make_unique<Scanner>(module_base);
    hooks_ = std::make_unique<HookEngine>(stubs_);
    patches_ = std::make_unique<PatchManager>(logger_, *scanner_, patcher_, stubs_);

    BuildApiTable();
    g_active_runtime = this;

    extensions_ = std::make_unique<ExtensionManager>(
        logger_, api_,
        [this](RiftExtHandle owner) { CleanupExtensionResources(owner); });

    RegisterBuiltinCommands();

    logger_.Log(RIFT_LOG_INFO, "loader", "Glitch v1.0.0 initialized (game_base=0x%llX, size=0x%zX)",
                static_cast<unsigned long long>(scanner_->ModuleBase()), scanner_->ImageSize());

    // 1. Apply declarative .rvt patches first.
    patches_->LoadDirectory(ResolvePath(config_.patches_dir), config_.disabled_patches);

    // 2. Load native C++/.dll extensions.
    extensions_->LoadDirectory(ResolvePath(config_.extensions_dir), config_.disabled_extensions);

    // 3. Notify extensions that all initial patches + extensions are loaded.
    extensions_->EmitEvent("loader.all_loaded", nullptr);

    initialized_ = true;
    return true;
}

void LoaderRuntime::Shutdown() {
    if (!initialized_) return;
    initialized_ = false;

    if (extensions_) {
        extensions_->EmitEvent("loader.shutdown", nullptr);
        extensions_->UnloadAll();
    }
    if (patches_) {
        patches_->UnloadAll();
    }
    if (hooks_) {
        hooks_->RemoveAll();
    }
    patcher_.DisableAll();
    stubs_.ReleaseAll();

    if (console_) {
        console_->Stop();
    }
    logger_.Log(RIFT_LOG_INFO, "loader", "Glitch shut down cleanly.");
    logger_.CloseFile();

    if (g_active_runtime == this) {
        g_active_runtime = nullptr;
    }
}

void LoaderRuntime::RegisterBuiltinCommands() {
    console_->RegisterCommand(
        RIFT_INVALID_HANDLE, "status", "Show loader status, ASLR base, patches, extensions, and stubs",
        [](int, const char* const*, void* ud) {
            auto* rt = static_cast<LoaderRuntime*>(ud);
            auto plist = rt->Patches().List();
            auto elist = rt->Extensions().List();
            auto hlist = rt->Hooks().List();
            auto sstats = rt->Stubs().GetStats();

            size_t p_on = 0;
            for (const auto& p : plist) if (p.enabled) ++p_on;

            std::ostringstream ss;
            ss << "=== RiftLoader Status ===\n"
               << "  Game Base  : 0x" << std::hex << std::uppercase << rt->GetScanner().ModuleBase()
               << " (ASLR slide: " << std::dec
               << (static_cast<int64_t>(rt->GetScanner().ModuleBase()) - static_cast<int64_t>(RIFT_STATIC_IMAGE_BASE))
               << ")\n"
               << "  Image Size : 0x" << std::hex << rt->GetScanner().ImageSize() << std::dec << "\n"
               << "  .rvt Patch : " << p_on << "/" << plist.size() << " enabled\n"
               << "  Extensions : " << elist.size() << " loaded\n"
               << "  Hooks      : " << hlist.size() << " installed\n"
               << "  Patch Stubs: " << sstats.live_allocs << " allocs (" << sstats.used_bytes
               << " / " << sstats.total_capacity << " B across " << sstats.page_count << " slab(s))\n";
            rt->GetConsole().Print(ss.str());
        },
        this);

    console_->RegisterCommand(
        RIFT_INVALID_HANDLE, "patch", "Manage .rvt patches: patch <list|enable|disable|toggle|reload> [name]",
        [](int argc, const char* const* argv, void* ud) {
            auto* rt = static_cast<LoaderRuntime*>(ud);
            if (argc < 2 || std::string(argv[1]) == "list") {
                auto list = rt->Patches().List();
                std::ostringstream ss;
                ss << "Declarative .rvt Patches (" << list.size() << "):\n";
                for (const auto& p : list) {
                    ss << "  [" << (p.error.empty() ? (p.enabled ? " ON " : "off ") : "ERR ") << "] "
                       << p.name << " (" << p.site_count << " sites)";
                    if (!p.error.empty()) ss << "  ERROR: " << p.error;
                    else if (!p.description.empty()) ss << " - " << p.description;
                    ss << "\n";
                }
                rt->GetConsole().Print(ss.str());
                return;
            }
            std::string sub = argv[1];
            if (sub == "reload") {
                rt->Patches().ReloadAll(rt->ResolvePath(rt->config_.patches_dir),
                                        rt->config_.disabled_patches);
                rt->GetConsole().Print("Reloaded .rvt patches.\n");
                return;
            }
            if (argc < 3) {
                rt->GetConsole().Print("Usage: patch <enable|disable|toggle> <name>\n");
                return;
            }
            std::string msg;
            if (sub == "enable") rt->Patches().EnableByName(argv[2], msg);
            else if (sub == "disable") rt->Patches().DisableByName(argv[2], msg);
            else if (sub == "toggle") rt->Patches().ToggleByName(argv[2], msg);
            else msg = "Unknown patch subcommand: " + sub;
            rt->GetConsole().Print(msg + "\n");
        },
        this);

    console_->RegisterCommand(
        RIFT_INVALID_HANDLE, "ext", "Manage native extensions: ext <list|load|unload|reload> [name|path]",
        [](int argc, const char* const* argv, void* ud) {
            auto* rt = static_cast<LoaderRuntime*>(ud);
            if (argc < 2 || std::string(argv[1]) == "list") {
                auto list = rt->Extensions().List();
                std::ostringstream ss;
                ss << "Loaded Extensions (" << list.size() << "):\n";
                for (const auto& e : list) {
                    ss << "  " << e.name << " v" << e.version;
                    if (!e.author.empty()) ss << " by " << e.author;
                    if (!e.description.empty()) ss << " - " << e.description;
                    ss << "\n";
                }
                rt->GetConsole().Print(ss.str());
                return;
            }
            std::string sub = argv[1];
            if (argc < 3) {
                rt->GetConsole().Print("Usage: ext <load|unload|reload> <name_or_dll>\n");
                return;
            }
            std::string msg;
            if (sub == "load") {
                std::string path = argv[2];
                if (!std::filesystem::exists(path)) {
                    path = (std::filesystem::path(rt->ResolvePath(rt->config_.extensions_dir)) / argv[2]).string();
                }
                rt->Extensions().LoadExtension(path, msg);
            } else if (sub == "unload") {
                rt->Extensions().UnloadByName(argv[2], msg);
            } else if (sub == "reload") {
                rt->Extensions().ReloadByName(argv[2], msg);
            } else {
                msg = "Unknown ext subcommand: " + sub;
            }
            rt->GetConsole().Print(msg + "\n");
        },
        this);

    console_->RegisterCommand(
        RIFT_INVALID_HANDLE, "mem", "Inspect memory: mem read <va:0x14...|0x...> [len] | mem scan <pattern>",
        [](int argc, const char* const* argv, void* ud) {
            auto* rt = static_cast<LoaderRuntime*>(ud);
            if (argc < 3) {
                rt->GetConsole().Print("Usage: mem read <va:0x14...|0x...> [len] | mem scan <byte pattern>\n");
                return;
            }
            std::string sub = argv[1];
            if (sub == "read") {
                std::string target = argv[2];
                uintptr_t addr = 0;
                if (target.rfind("va:", 0) == 0) {
                    uint64_t va = std::strtoull(target.c_str() + 3, nullptr, 0);
                    addr = rt->GetScanner().VaToLive(va);
                } else {
                    uint64_t v = std::strtoull(target.c_str(), nullptr, 0);
                    // Convenience: treat 0x14xxxxxxx static VAs automatically if outside live range.
                    if (v >= RIFT_STATIC_IMAGE_BASE && v < RIFT_STATIC_IMAGE_BASE + 0x20000000ULL &&
                        rt->GetScanner().ModuleBase() != RIFT_STATIC_IMAGE_BASE) {
                        addr = rt->GetScanner().VaToLive(v);
                    } else {
                        addr = static_cast<uintptr_t>(v);
                    }
                }
                size_t len = (argc >= 4) ? static_cast<size_t>(std::strtoull(argv[3], nullptr, 0)) : 32;
                if (len == 0 || len > 512) len = 32;

                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) ||
                    mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS)) {
                    rt->GetConsole().Print("Address is not readable.\n");
                    return;
                }
                std::ostringstream ss;
                ss << "0x" << std::hex << std::uppercase << addr << " (static VA 0x"
                   << rt->GetScanner().LiveToVa(addr) << "):\n";
                const auto* p = reinterpret_cast<const uint8_t*>(addr);
                for (size_t i = 0; i < len; i += 16) {
                    ss << "  +" << std::setw(3) << std::setfill('0') << i << ": ";
                    for (size_t j = 0; j < 16 && i + j < len; ++j) {
                        ss << std::setw(2) << std::setfill('0') << static_cast<unsigned>(p[i + j]) << " ";
                    }
                    ss << "\n";
                }
                rt->GetConsole().Print(ss.str());
            } else if (sub == "scan") {
                std::string pat;
                for (int i = 2; i < argc; ++i) {
                    if (i > 2) pat.push_back(' ');
                    pat += argv[i];
                }
                uintptr_t found = 0;
                RiftResult r = rt->GetScanner().FindPattern(pat, found);
                if (r == RIFT_OK) {
                    std::ostringstream ss;
                    ss << "Found at live 0x" << std::hex << std::uppercase << found
                       << " (static VA 0x" << rt->GetScanner().LiveToVa(found) << ")\n";
                    rt->GetConsole().Print(ss.str());
                } else {
                    rt->GetConsole().Print("Pattern not found.\n");
                }
            }
        },
        this);

    console_->RegisterCommand(
        RIFT_INVALID_HANDLE, "loglevel", "Set log verbosity: loglevel <trace|debug|info|warn|error>",
        [](int argc, const char* const* argv, void* ud) {
            auto* rt = static_cast<LoaderRuntime*>(ud);
            if (argc < 2) {
                rt->GetConsole().Print(std::string("Current log level: ") +
                                       Logger::LevelName(rt->Log().GetMinLevel()) + "\n");
                return;
            }
            RiftLogLevel lvl = Logger::ParseLevel(argv[1], rt->Log().GetMinLevel());
            rt->Log().SetMinLevel(lvl);
            rt->GetConsole().Print(std::string("Log level set to ") + Logger::LevelName(lvl) + "\n");
        },
        this);
}

} // namespace riftloader
