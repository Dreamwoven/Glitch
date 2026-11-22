#pragma once

#include "stub_alloc.hpp"
#include "rift_sdk.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace riftloader {

struct HookRecordInfo {
    RiftHookHandle handle = RIFT_INVALID_HANDLE;
    RiftExtHandle owner = RIFT_INVALID_HANDLE;
    std::string id;
    uintptr_t target = 0;
    uintptr_t detour = 0;
    uintptr_t trampoline = 0;
    bool active = false;
};

class HookEngine {
public:
    explicit HookEngine(StubAllocator& stub_alloc);
    ~HookEngine();

    HookEngine(const HookEngine&) = delete;
    HookEngine& operator=(const HookEngine&) = delete;

    RiftResult Create(
        RiftExtHandle owner,
        const std::string& id,
        void* target,
        void* detour,
        void** out_original,
        bool enable_now,
        RiftHookHandle* out_handle);

    RiftResult Enable(RiftHookHandle handle);
    RiftResult Disable(RiftHookHandle handle);
    RiftResult Remove(RiftHookHandle handle);
    void RemoveByOwner(RiftExtHandle owner);
    void RemoveAll();

    std::vector<HookRecordInfo> List() const;

private:
    struct Entry {
        RiftHookHandle handle = RIFT_INVALID_HANDLE;
        RiftExtHandle owner = RIFT_INVALID_HANDLE;
        std::string id;
        uintptr_t target = 0;
        uintptr_t detour = 0;
        void* stub_block = nullptr;
        uintptr_t relay_va = 0;
        uintptr_t trampoline_va = 0;
        std::vector<uint8_t> orig_bytes;
        std::vector<uint8_t> patch_bytes;
        bool active = false;
    };

    StubAllocator& stub_alloc_;
    mutable std::mutex mutex_;
    RiftHookHandle next_handle_ = 1;
    std::unordered_map<RiftHookHandle, Entry> entries_;
};

} // namespace riftloader
