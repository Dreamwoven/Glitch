#include "loader_main.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <filesystem>
#include <memory>
#include <string>

namespace {

std::unique_ptr<riftloader::LoaderRuntime> g_dll_runtime;

std::string GetExeDirectory() {
    char buf[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return ".";
    return std::filesystem::path(buf).parent_path().string();
}

} // namespace

extern "C" {

__declspec(dllexport) bool RiftLoader_Initialize(void) {
    if (g_dll_runtime && g_dll_runtime->IsInitialized()) return true;
    g_dll_runtime = std::make_unique<riftloader::LoaderRuntime>();
    return g_dll_runtime->Initialize(GetExeDirectory(), 0, true);
}

__declspec(dllexport) void RiftLoader_Shutdown(void) {
    if (g_dll_runtime) {
        g_dll_runtime->Shutdown();
        g_dll_runtime.reset();
    }
}

} // extern "C"

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_DETACH) {
        if (reserved == nullptr) {
            // Dynamic FreeLibrary: perform full teardown.
            RiftLoader_Shutdown();
        } else if (g_dll_runtime) {
            // Process terminating: flush log cleanly without calling FreeLibrary under loader lock.
            g_dll_runtime->Log().Log(RIFT_LOG_INFO, "loader", "Process exiting; flushing log.");
            g_dll_runtime->Log().CloseFile();
        }
    }
    return TRUE;
}
