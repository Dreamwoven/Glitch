#include "memory_patch.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstring>

namespace riftloader {

MemoryPatcher::~MemoryPatcher() {
    DisableAll();
}

bool MemoryPatcher::WriteProtectedMemory(uintptr_t addr, const uint8_t* data, size_t len) {
    if (!addr || !data || len == 0) return false;
    void* ptr = reinterpret_cast<void*>(addr);
    DWORD old_prot = 0;
    if (!VirtualProtect(ptr, len, PAGE_EXECUTE_READWRITE, &old_prot)) {
        return false;
    }
    std::memcpy(ptr, data, len);
    DWORD dummy = 0;
    VirtualProtect(ptr, len, old_prot, &dummy);
    FlushInstructionCache(GetCurrentProcess(), ptr, len);
    return true;
}

bool MemoryPatcher::HasActiveConflictLocked(uintptr_t addr, size_t len, RiftPatchHandle ignore_handle) const {
    const uintptr_t end = addr + len;
    for (const auto& kv : entries_) {
        const Entry& e = kv.second;
        if (!e.active || e.handle == ignore_handle) continue;
        const uintptr_t e_end = e.address + e.patch_bytes.size();
        if (addr < e_end && e.address < end) {
            return true;
        }
    }
    return false;
}

RiftResult MemoryPatcher::Create(
    RiftExtHandle owner,
    const std::string& id,
    uintptr_t address,
    const uint8_t* expected_orig,
    const uint8_t* patch_bytes,
    size_t length,
    bool enable_now,
    RiftPatchHandle* out_handle) {
    if (!address || !patch_bytes || length == 0) {
        return RIFT_ERR_INVALID_ARG;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    const bool has_conflict = HasActiveConflictLocked(address, length, RIFT_INVALID_HANDLE);
    if (has_conflict && enable_now) {
        return RIFT_ERR_CONFLICT;
    }

    std::vector<uint8_t> orig;
    if (has_conflict) {
        // An overlapping patch is currently active while this patch is being registered disabled.
        // We cannot snapshot pristine bytes from live memory, so require expected_orig; Enable()
        // will verify the restored pristine bytes once the conflicting patch is disabled.
        if (!expected_orig) {
            return RIFT_ERR_CONFLICT;
        }
        orig.assign(expected_orig, expected_orig + length);
    } else {
        orig.resize(length);
        std::memcpy(orig.data(), reinterpret_cast<const void*>(address), length);
        if (expected_orig && std::memcmp(orig.data(), expected_orig, length) != 0) {
            return RIFT_ERR_BYTES_MISMATCH;
        }
    }

    Entry e;
    e.handle = next_handle_++;
    e.owner = owner;
    e.id = id;
    e.address = address;
    e.orig_bytes = std::move(orig);
    e.patch_bytes.assign(patch_bytes, patch_bytes + length);
    e.active = false;

    if (enable_now) {
        if (!WriteProtectedMemory(e.address, e.patch_bytes.data(), e.patch_bytes.size())) {
            return RIFT_ERR_PROTECT_FAILED;
        }
        e.active = true;
    }

    RiftPatchHandle h = e.handle;
    entries_.emplace(h, std::move(e));
    if (out_handle) *out_handle = h;
    return RIFT_OK;
}

RiftResult MemoryPatcher::Enable(RiftPatchHandle handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return RIFT_ERR_NOT_FOUND;
    Entry& e = it->second;
    if (e.active) return RIFT_OK;

    if (HasActiveConflictLocked(e.address, e.patch_bytes.size(), e.handle)) {
        return RIFT_ERR_CONFLICT;
    }
    if (std::memcmp(reinterpret_cast<const void*>(e.address),
                    e.orig_bytes.data(), e.orig_bytes.size()) != 0) {
        return RIFT_ERR_BYTES_MISMATCH;
    }
    if (!WriteProtectedMemory(e.address, e.patch_bytes.data(), e.patch_bytes.size())) {
        return RIFT_ERR_PROTECT_FAILED;
    }
    e.active = true;
    return RIFT_OK;
}

RiftResult MemoryPatcher::Disable(RiftPatchHandle handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return RIFT_ERR_NOT_FOUND;
    Entry& e = it->second;
    if (!e.active) return RIFT_OK;

    if (!WriteProtectedMemory(e.address, e.orig_bytes.data(), e.orig_bytes.size())) {
        return RIFT_ERR_PROTECT_FAILED;
    }
    e.active = false;
    return RIFT_OK;
}

RiftResult MemoryPatcher::Remove(RiftPatchHandle handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return RIFT_ERR_NOT_FOUND;
    if (it->second.active) {
        WriteProtectedMemory(it->second.address,
                             it->second.orig_bytes.data(),
                             it->second.orig_bytes.size());
    }
    entries_.erase(it);
    return RIFT_OK;
}

void MemoryPatcher::RemoveByOwner(RiftExtHandle owner) {
    if (owner == RIFT_INVALID_HANDLE) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end(); ) {
        if (it->second.owner == owner) {
            if (it->second.active) {
                WriteProtectedMemory(it->second.address,
                                     it->second.orig_bytes.data(),
                                     it->second.orig_bytes.size());
            }
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void MemoryPatcher::DisableAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& kv : entries_) {
        if (kv.second.active) {
            WriteProtectedMemory(kv.second.address,
                                 kv.second.orig_bytes.data(),
                                 kv.second.orig_bytes.size());
            kv.second.active = false;
        }
    }
}

std::vector<PatchRecordInfo> MemoryPatcher::List() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PatchRecordInfo> out;
    out.reserve(entries_.size());
    for (const auto& kv : entries_) {
        const Entry& e = kv.second;
        out.push_back({e.handle, e.owner, e.id, e.address, e.patch_bytes.size(), e.active});
    }
    return out;
}

} // namespace riftloader
