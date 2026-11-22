#pragma once

#include "stub_alloc.hpp"
#include "config.hpp"
#include "console.hpp"
#include "extension_manager.hpp"
#include "hook_engine.hpp"
#include "logger.hpp"
#include "memory_patch.hpp"
#include "patch_manager.hpp"
#include "rift_sdk.h"
#include "scanner.hpp"

#include <memory>
#include <string>

namespace riftloader {

// Owns and wires all RiftLoader subsystems without leaking global state.
class LoaderRuntime {
public:
    LoaderRuntime() = default;
    ~LoaderRuntime();

    LoaderRuntime(const LoaderRuntime&) = delete;
    LoaderRuntime& operator=(const LoaderRuntime&) = delete;

    bool Initialize(const std::string& game_dir, uintptr_t module_base = 0, bool allow_console = true);
    void Shutdown();

    bool IsInitialized() const { return initialized_; }
    const RiftLoaderAPI& Api() const { return api_; }

    Logger& Log() { return logger_; }
    Scanner& GetScanner() { return *scanner_; }
    StubAllocator& Stubs() { return stubs_; }
    MemoryPatcher& Patcher() { return patcher_; }
    HookEngine& Hooks() { return *hooks_; }
    PatchManager& Patches() { return *patches_; }
    ExtensionManager& Extensions() { return *extensions_; }
    Console& GetConsole() { return *console_; }

private:
    void BuildApiTable();
    void RegisterBuiltinCommands();
    void CleanupExtensionResources(RiftExtHandle owner);
    std::string ResolvePath(const std::string& rel_or_abs) const;

    bool initialized_ = false;
    std::string game_dir_;
    std::string loader_dir_;
    std::string config_path_;
    LoaderConfig config_;

    Logger logger_;
    StubAllocator stubs_;
    MemoryPatcher patcher_;
    std::unique_ptr<Scanner> scanner_;
    std::unique_ptr<HookEngine> hooks_;
    std::unique_ptr<PatchManager> patches_;
    std::unique_ptr<Console> console_;
    std::unique_ptr<ExtensionManager> extensions_;

    RiftLoaderAPI api_{};
};

} // namespace riftloader

extern "C" {
__declspec(dllexport) bool RiftLoader_Initialize(void);
__declspec(dllexport) void RiftLoader_Shutdown(void);
}
