#pragma once

#include "rift_sdk.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace riftloader {

struct PatchRecordInfo {
    RiftPatchHandle handle = RIFT_INVALID_HANDLE;
    RiftExtHandle owner = RIFT_INVALID_HANDLE;
    std::string id;
    uintptr_t address = 0;
    size_t length = 0;
    bool active = false;
};

class MemoryPatcher {
public:
    MemoryPatcher() = default;
    ~MemoryPatcher();

    MemoryPatcher(const MemoryPatcher&) = delete;
    MemoryPatcher& operator=(const MemoryPatcher&) = delete;

    RiftResult Create(
        RiftExtHandle owner,
        const std::string& id,
        uintptr_t address,
        const uint8_t* expected_orig,
        const uint8_t* patch_bytes,
        size_t length,
        bool enable_now,
        RiftPatchHandle* out_handle);

    RiftResult Enable(RiftPatchHandle handle);
    RiftResult Disable(RiftPatchHandle handle);
    RiftResult Remove(RiftPatchHandle handle);
    void RemoveByOwner(RiftExtHandle owner);
    void DisableAll();

    std::vector<PatchRecordInfo> List() const;

    static bool WriteProtectedMemory(uintptr_t addr, const uint8_t* data, size_t len);

private:
    struct Entry {
        RiftPatchHandle handle = RIFT_INVALID_HANDLE;
        RiftExtHandle owner = RIFT_INVALID_HANDLE;
        std::string id;
        uintptr_t address = 0;
        std::vector<uint8_t> orig_bytes;
        std::vector<uint8_t> patch_bytes;
        bool active = false;
    };

    bool HasActiveConflictLocked(uintptr_t addr, size_t len, RiftPatchHandle ignore_handle) const;

    mutable std::mutex mutex_;
    RiftPatchHandle next_handle_ = 1;
    std::unordered_map<RiftPatchHandle, Entry> entries_;
};

} // namespace riftloader
