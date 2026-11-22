/*
 * Thin winmm.dll proxy for RiftLoader.
 *
 * 1. Forwards all 181 System32\winmm.dll exports transparently (including NONAME ord 2).
 * 2. In DllMain(DLL_PROCESS_ATTACH), installs a loader-lock-safe 14-byte one-shot
 *    trampoline on the host EXE's PE EntryPoint (NO LoadLibrary inside DllMain!).
 * 3. When Windows jumps to the host EntryPoint (OS loader lock free, before _initterm
 *    and before WinMain), ProxyOnHostEntryPoint restores the original 14 bytes,
 *    loads RiftLoader.dll from the game directory, calls RiftLoader_Initialize(),
 *    and resumes the real host EntryPoint seamlessly.
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <cstring>

#include "winmm_names.inc"

extern "C" {
FARPROC g_winmm_procs[kWinmmExportCount] = {};
void ProxyEntryPointTrampoline(void);
}

namespace {

INIT_ONCE g_winmm_init_once = INIT_ONCE_STATIC_INIT;
HMODULE g_real_winmm = nullptr;
HMODULE g_loader_dll = nullptr;
HMODULE g_self_module = nullptr;

uintptr_t g_entry_point = 0;
uint8_t g_entry_orig[14] = {};
bool g_entry_hooked = false;

BOOL CALLBACK ResolveRealWinmmOnce(PINIT_ONCE, PVOID, PVOID*) {
    wchar_t sys_dir[MAX_PATH] = {};
    UINT len = GetSystemDirectoryW(sys_dir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH - 16) return FALSE;

    wchar_t real_path[MAX_PATH] = {};
    lstrcpyW(real_path, sys_dir);
    lstrcatW(real_path, L"\\winmm.dll");

    g_real_winmm = LoadLibraryW(real_path);
    if (!g_real_winmm) return FALSE;

    for (size_t i = 0; i < kWinmmExportCount; ++i) {
        const auto& desc = kWinmmExports[i];
        if (desc.name) {
            g_winmm_procs[i] = GetProcAddress(g_real_winmm, desc.name);
        } else {
            g_winmm_procs[i] = GetProcAddress(g_real_winmm, MAKEINTRESOURCEA(desc.ordinal));
        }
    }
    return TRUE;
}

bool InstallEntryPointHook() {
    HMODULE host = GetModuleHandleW(nullptr);
    if (!host) return false;

    const auto base = reinterpret_cast<uintptr_t>(host);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.AddressOfEntryPoint == 0) {
        return false;
    }

    g_entry_point = base + nt->OptionalHeader.AddressOfEntryPoint;
    void* ep_ptr = reinterpret_cast<void*>(g_entry_point);

    DWORD old_prot = 0;
    if (!VirtualProtect(ep_ptr, sizeof(g_entry_orig), PAGE_EXECUTE_READWRITE, &old_prot)) {
        return false;
    }

    std::memcpy(g_entry_orig, ep_ptr, sizeof(g_entry_orig));

    // Write 14-byte absolute jump: FF 25 00 00 00 00 <u64 ProxyEntryPointTrampoline>
    uint8_t jmp[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    uint64_t dst = reinterpret_cast<uint64_t>(&ProxyEntryPointTrampoline);
    std::memcpy(jmp + 6, &dst, 8);
    std::memcpy(ep_ptr, jmp, sizeof(jmp));

    DWORD dummy = 0;
    VirtualProtect(ep_ptr, sizeof(g_entry_orig), old_prot, &dummy);
    FlushInstructionCache(GetCurrentProcess(), ep_ptr, sizeof(g_entry_orig));
    g_entry_hooked = true;
    return true;
}

void RestoreEntryPoint() {
    if (!g_entry_hooked || !g_entry_point) return;
    void* ep_ptr = reinterpret_cast<void*>(g_entry_point);
    DWORD old_prot = 0;
    if (VirtualProtect(ep_ptr, sizeof(g_entry_orig), PAGE_EXECUTE_READWRITE, &old_prot)) {
        std::memcpy(ep_ptr, g_entry_orig, sizeof(g_entry_orig));
        DWORD dummy = 0;
        VirtualProtect(ep_ptr, sizeof(g_entry_orig), old_prot, &dummy);
        FlushInstructionCache(GetCurrentProcess(), ep_ptr, sizeof(g_entry_orig));
    }
    g_entry_hooked = false;
}

void LoadCoreDll() {
    wchar_t dll_path[MAX_PATH] = {};
    DWORD len = GetModuleFileNameW(g_self_module, dll_path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return;

    wchar_t* slash = wcsrchr(dll_path, L'\\');
    if (slash) {
        *(slash + 1) = L'\0';
    }
    lstrcatW(dll_path, L"Glitch.dll");

    g_loader_dll = LoadLibraryW(dll_path);
    if (!g_loader_dll) {
        // Also try inside glitch\Glitch.dll as a fallback
        if (slash) *(slash + 1) = L'\0';
        lstrcatW(dll_path, L"glitch\\Glitch.dll");
        g_loader_dll = LoadLibraryW(dll_path);
    }
    if (!g_loader_dll) return;

    using InitFn = bool (*)(void);
    auto init_fn = reinterpret_cast<InitFn>(GetProcAddress(g_loader_dll, "RiftLoader_Initialize"));
    if (init_fn) {
        init_fn();
    }
}

} // namespace

extern "C" {

void WinmmEnsureResolved(void) {
    InitOnceExecuteOnce(&g_winmm_init_once, ResolveRealWinmmOnce, nullptr, nullptr);
}

uintptr_t ProxyOnHostEntryPoint(void) {
    // 1. Restore the original 14 bytes of host EntryPoint immediately.
    RestoreEntryPoint();
    // 2. Ensure System32\winmm.dll exports are resolved now that loader lock is free.
    WinmmEnsureResolved();
    // 3. Load RiftLoader.dll and apply all pre-init patches + native extensions!
    LoadCoreDll();
    // 4. Return original EntryPoint so trampoline jumps straight into WinMainCRTStartup.
    return g_entry_point;
}

} // extern "C"

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self_module = hinst;
        DisableThreadLibraryCalls(hinst);
        // Zero LoadLibrary calls inside DllMain - only patch EntryPoint for clean bootstrap!
        InstallEntryPointHook();
    } else if (reason == DLL_PROCESS_DETACH && reserved == nullptr) {
        if (g_loader_dll) {
            using ShutdownFn = void (*)(void);
            auto shutdown_fn = reinterpret_cast<ShutdownFn>(
                GetProcAddress(g_loader_dll, "RiftLoader_Shutdown"));
            if (shutdown_fn) shutdown_fn();
        }
    }
    return TRUE;
}
