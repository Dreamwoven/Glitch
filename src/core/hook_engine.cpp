#include "hook_engine.hpp"
#include "memory_patch.hpp"
#include "x64_disasm.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstring>

namespace riftloader {

namespace {
constexpr size_t kRelaySize = 16;       // 14-byte abs jmp + 2 bytes pad for 16-byte alignment
constexpr size_t kMaxTrampoline = 112;  // Generous room for relocated prologue + back jmp
constexpr size_t kStubBlockSize = kRelaySize + kMaxTrampoline;
} // namespace

HookEngine::HookEngine(StubAllocator& stub_alloc) : stub_alloc_(stub_alloc) {}

HookEngine::~HookEngine() {
    RemoveAll();
}

RiftResult HookEngine::Create(
    RiftExtHandle owner,
    const std::string& id,
    void* target,
    void* detour,
    void** out_original,
    bool enable_now,
    RiftHookHandle* out_handle) {
    if (!target || !detour) return RIFT_ERR_INVALID_ARG;

    const uintptr_t target_va = reinterpret_cast<uintptr_t>(target);
    const uintptr_t detour_va = reinterpret_cast<uintptr_t>(detour);

    std::lock_guard<std::mutex> lock(mutex_);

    // Prevent hooking the exact same address twice.
    for (const auto& kv : entries_) {
        if (kv.second.target == target_va) {
            return RIFT_ERR_CONFLICT;
        }
    }

    // Allocate a single near-2GB block holding [relay | trampoline].
    void* stub = stub_alloc_.Alloc(target_va, kStubBlockSize, owner);
    if (!stub) return RIFT_ERR_ALLOC_FAILED;

    const uintptr_t relay_va = reinterpret_cast<uintptr_t>(stub);
    const uintptr_t tramp_va = relay_va + kRelaySize;

    // Verify 5-byte rel32 reaches relay_va from target_va.
    const int64_t rel = static_cast<int64_t>(relay_va) - static_cast<int64_t>(target_va + 5);
    const bool use_near_jmp = (rel >= INT32_MIN && rel <= INT32_MAX);
    const size_t min_stolen = use_near_jmp ? 5 : 14;

    std::vector<uint8_t> trampoline;
    const size_t stolen = RelocatePrologue(
        reinterpret_cast<const uint8_t*>(target_va),
        target_va,
        min_stolen,
        tramp_va,
        trampoline);

    if (stolen == 0 || trampoline.size() > kMaxTrampoline) {
        stub_alloc_.Free(stub);
        return RIFT_ERR_DECODE_FAILED;
    }

    // Write relay stub: FF 25 00 00 00 00 <u64 detour_va>
    uint8_t relay[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    uint64_t d64 = static_cast<uint64_t>(detour_va);
    std::memcpy(relay + 6, &d64, 8);
    std::memcpy(stub, relay, sizeof(relay));

    // Write trampoline bytes.
    std::memcpy(reinterpret_cast<void*>(tramp_va), trampoline.data(), trampoline.size());
    FlushInstructionCache(GetCurrentProcess(), stub, kStubBlockSize);

    // Prepare entry patch bytes (E9 rel32 + NOP pad, or 14-byte abs jmp + NOP pad).
    std::vector<uint8_t> patch(stolen, 0x90);
    if (use_near_jmp) {
        patch[0] = 0xE9;
        int32_t rel32 = static_cast<int32_t>(rel);
        std::memcpy(patch.data() + 1, &rel32, 4);
    } else {
        std::memcpy(patch.data(), relay, 14);
    }

    Entry e;
    e.handle = next_handle_++;
    e.owner = owner;
    e.id = id;
    e.target = target_va;
    e.detour = detour_va;
    e.stub_block = stub;
    e.relay_va = relay_va;
    e.trampoline_va = tramp_va;
    e.orig_bytes.assign(reinterpret_cast<const uint8_t*>(target_va),
                        reinterpret_cast<const uint8_t*>(target_va) + stolen);
    e.patch_bytes = std::move(patch);
    e.active = false;

    if (out_original) {
        *out_original = reinterpret_cast<void*>(tramp_va);
    }

    if (enable_now) {
        if (!MemoryPatcher::WriteProtectedMemory(e.target, e.patch_bytes.data(), e.patch_bytes.size())) {
            stub_alloc_.Free(stub);
            return RIFT_ERR_PROTECT_FAILED;
        }
        e.active = true;
    }

    RiftHookHandle h = e.handle;
    entries_.emplace(h, std::move(e));
    if (out_handle) *out_handle = h;
    return RIFT_OK;
}

RiftResult HookEngine::Enable(RiftHookHandle handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return RIFT_ERR_NOT_FOUND;
    Entry& e = it->second;
    if (e.active) return RIFT_OK;

    if (!MemoryPatcher::WriteProtectedMemory(e.target, e.patch_bytes.data(), e.patch_bytes.size())) {
        return RIFT_ERR_PROTECT_FAILED;
    }
    e.active = true;
    return RIFT_OK;
}

RiftResult HookEngine::Disable(RiftHookHandle handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return RIFT_ERR_NOT_FOUND;
    Entry& e = it->second;
    if (!e.active) return RIFT_OK;

    if (!MemoryPatcher::WriteProtectedMemory(e.target, e.orig_bytes.data(), e.orig_bytes.size())) {
        return RIFT_ERR_PROTECT_FAILED;
    }
    e.active = false;
    return RIFT_OK;
}

RiftResult HookEngine::Remove(RiftHookHandle handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return RIFT_ERR_NOT_FOUND;
    Entry& e = it->second;
    if (e.active) {
        MemoryPatcher::WriteProtectedMemory(e.target, e.orig_bytes.data(), e.orig_bytes.size());
    }
    if (e.stub_block) {
        stub_alloc_.Free(e.stub_block);
    }
    entries_.erase(it);
    return RIFT_OK;
}

void HookEngine::RemoveByOwner(RiftExtHandle owner) {
    if (owner == RIFT_INVALID_HANDLE) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end(); ) {
        if (it->second.owner == owner) {
            if (it->second.active) {
                MemoryPatcher::WriteProtectedMemory(it->second.target,
                                                    it->second.orig_bytes.data(),
                                                    it->second.orig_bytes.size());
            }
            if (it->second.stub_block) {
                stub_alloc_.Free(it->second.stub_block);
            }
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void HookEngine::RemoveAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& kv : entries_) {
        if (kv.second.active) {
            MemoryPatcher::WriteProtectedMemory(kv.second.target,
                                                kv.second.orig_bytes.data(),
                                                kv.second.orig_bytes.size());
        }
        if (kv.second.stub_block) {
            stub_alloc_.Free(kv.second.stub_block);
        }
    }
    entries_.clear();
}

std::vector<HookRecordInfo> HookEngine::List() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HookRecordInfo> out;
    out.reserve(entries_.size());
    for (const auto& kv : entries_) {
        const Entry& e = kv.second;
        out.push_back({e.handle, e.owner, e.id, e.target, e.detour, e.trampoline_va, e.active});
    }
    return out;
}

} // namespace riftloader
