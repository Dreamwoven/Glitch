#pragma once
/*
 * RiftLoader Native Extension SDK (Pure C ABI)
 *
 * SourceMod-style versioned extension interface for Ratchet & Clank: Rift Apart (PC).
 * Drop compiled x64 .dll extensions into <game_dir>/riftloader/extensions/.
 *
 * Required DLL exports:
 *   RIFT_EXT_EXPORT bool RiftExt_Query(RiftExtensionInfo* out_info);
 *   RIFT_EXT_EXPORT bool RiftExt_Load(const RiftLoaderAPI* api, RiftExtHandle self);
 *   RIFT_EXT_EXPORT void RiftExt_Unload(void);
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIFT_SDK_API_VERSION 1u
#define RIFT_STATIC_IMAGE_BASE UINT64_C(0x140000000)

#if defined(_WIN32)
#define RIFT_EXT_EXPORT __declspec(dllexport)
#else
#define RIFT_EXT_EXPORT __attribute__((visibility("default")))
#endif

typedef uint64_t RiftExtHandle;
typedef uint64_t RiftPatchHandle;
typedef uint64_t RiftHookHandle;
typedef uint64_t RiftEventSubHandle;

#define RIFT_INVALID_HANDLE UINT64_C(0)

typedef enum RiftLogLevel {
    RIFT_LOG_TRACE = 0,
    RIFT_LOG_DEBUG = 1,
    RIFT_LOG_INFO  = 2,
    RIFT_LOG_WARN  = 3,
    RIFT_LOG_ERROR = 4
} RiftLogLevel;

typedef enum RiftResult {
    RIFT_OK                  = 0,
    RIFT_ERR_INVALID_ARG     = 1,
    RIFT_ERR_NOT_FOUND       = 2,
    RIFT_ERR_BYTES_MISMATCH  = 3,
    RIFT_ERR_CONFLICT        = 4,
    RIFT_ERR_ALLOC_FAILED    = 5,
    RIFT_ERR_PROTECT_FAILED  = 6,
    RIFT_ERR_DECODE_FAILED   = 7,
    RIFT_ERR_ALREADY_EXISTS  = 8,
    RIFT_ERR_INTERNAL        = 9
} RiftResult;

typedef struct RiftExtensionInfo {
    uint32_t    struct_size;   /* Must be sizeof(RiftExtensionInfo) */
    uint32_t    api_version;   /* Must be RIFT_SDK_API_VERSION */
    const char* name;          /* Unique short identifier, e.g. "fogspan" */
    const char* version;       /* Semver string, e.g. "0.1.0" */
    const char* author;        /* Author name */
    const char* description;   /* One-line summary */
} RiftExtensionInfo;

typedef void (*RiftCommandFn)(int argc, const char* const* argv, void* user_data);
typedef void (*RiftEventFn)(const char* event_name, const void* payload, void* user_data);

typedef struct RiftLoaderAPI {
    uint32_t struct_size;
    uint32_t api_version;

    /* ---- Logging & Console ---- */
    void (*Log)(RiftLogLevel level, const char* tag, const char* fmt, ...);
    void (*ConsolePrint)(const char* text);

    /* ---- Module & ASLR Address Helpers ---- */
    uintptr_t (*GetGameBase)(void);
    size_t    (*GetGameImageSize)(void);
    /* Converts static 0x14xxxxxxx VA from RE docs to live ASLR address */
    uintptr_t (*VaToLive)(uint64_t static_va);
    uintptr_t (*RvaToLive)(uint32_t rva);
    uint64_t  (*LiveToVa)(uintptr_t live_addr);

    /* ---- Byte Pattern Scanning ---- */
    /* Pattern format: "48 8D 81 ?? 1B 01 00" (? or ?? = wildcard). */
    RiftResult (*ScanPattern)(const char* pattern, uintptr_t* out_addr);
    RiftResult (*ScanSection)(const char* section_name, const char* pattern, uintptr_t* out_addr);

    /* ---- Verified Byte Patches (auto-reverted if owner unloads) ---- */
    RiftResult (*PatchCreate)(
        RiftExtHandle owner,
        const char* id,
        uintptr_t live_addr,
        const uint8_t* expected_orig, /* Optional (nullptr skips verify) */
        const uint8_t* patch_bytes,
        size_t length,
        bool enable_now,
        RiftPatchHandle* out_handle);
    RiftResult (*PatchEnable)(RiftPatchHandle handle);
    RiftResult (*PatchDisable)(RiftPatchHandle handle);
    RiftResult (*PatchRemove)(RiftPatchHandle handle);

    /* ---- x64 Function Detours (auto-unhooked if owner unloads) ---- */
    RiftResult (*HookCreate)(
        RiftExtHandle owner,
        const char* id,
        void* target,
        void* detour,
        void** out_original,
        bool enable_now,
        RiftHookHandle* out_handle);
    RiftResult (*HookEnable)(RiftHookHandle handle);
    RiftResult (*HookDisable)(RiftHookHandle handle);
    RiftResult (*HookRemove)(RiftHookHandle handle);

    /* ---- Near +-2GB Executable Stub Allocator ---- */
    void* (*StubAlloc)(RiftExtHandle owner, size_t size);
    void  (*StubFree)(void* ptr);

    /* ---- Inter-Extension Shared Interfaces (SourceMod IShareSys style) ---- */
    RiftResult  (*RegisterInterface)(RiftExtHandle owner, const char* name, uint32_t version, void* iface_ptr);
    void*       (*GetInterface)(const char* name, uint32_t min_version);

    /* ---- Named Event Bus ---- */
    /* Built-in events: "loader.all_loaded", "loader.shutdown" */
    RiftEventSubHandle (*SubscribeEvent)(RiftExtHandle owner, const char* event_name, RiftEventFn cb, void* user_data);
    void               (*UnsubscribeEvent)(RiftEventSubHandle sub);
    void               (*EmitEvent)(const char* event_name, const void* payload);

    /* ---- Console Commands (auto-unregistered if owner unloads) ---- */
    RiftResult (*RegisterCommand)(RiftExtHandle owner, const char* name, const char* help, RiftCommandFn cb, void* user_data);
    void       (*UnregisterCommand)(const char* name);

    /* ---- Paths (UTF-8) ---- */
    const char* (*GetGameDir)(void);
    const char* (*GetLoaderDir)(void);
} RiftLoaderAPI;

/* Function pointer types for the 3 extension DLL exports */
typedef bool (*RiftExtQueryFn)(RiftExtensionInfo* out_info);
typedef bool (*RiftExtLoadFn)(const RiftLoaderAPI* api, RiftExtHandle self);
typedef void (*RiftExtUnloadFn)(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
