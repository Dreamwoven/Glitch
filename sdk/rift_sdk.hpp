#pragma once
/*
 * RiftLoader Native Extension SDK (C++17 Convenience Wrapper)
 *
 * Optional header-only wrapper over rift_sdk.h providing typed hooks,
 * RAII guards, and cleaner boilerplate for C++ extension authors.
 */

#include "rift_sdk.h"

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <vector>

namespace rift {

class Context {
public:
    Context() = default;
    Context(const RiftLoaderAPI* api, RiftExtHandle self) : api_(api), self_(self) {}

    bool Valid() const { return api_ != nullptr && self_ != RIFT_INVALID_HANDLE; }
    const RiftLoaderAPI* Raw() const { return api_; }
    RiftExtHandle Handle() const { return self_; }

    uintptr_t GameBase() const { return api_->GetGameBase(); }
    uintptr_t VaToLive(uint64_t static_va) const { return api_->VaToLive(static_va); }
    uintptr_t RvaToLive(uint32_t rva) const { return api_->RvaToLive(rva); }

    template <typename FnPtr>
    RiftResult HookVa(const char* id, uint64_t static_va, FnPtr detour, FnPtr* out_original,
                      bool enable_now = true, RiftHookHandle* out_handle = nullptr) const {
        void* orig = nullptr;
        RiftHookHandle h = RIFT_INVALID_HANDLE;
        RiftResult r = api_->HookCreate(
            self_, id, reinterpret_cast<void*>(api_->VaToLive(static_va)),
            reinterpret_cast<void*>(detour), &orig, enable_now, &h);
        if (r == RIFT_OK) {
            if (out_original) *out_original = reinterpret_cast<FnPtr>(orig);
            if (out_handle) *out_handle = h;
        }
        return r;
    }

    template <typename FnPtr>
    RiftResult HookLive(const char* id, void* target, FnPtr detour, FnPtr* out_original,
                        bool enable_now = true, RiftHookHandle* out_handle = nullptr) const {
        void* orig = nullptr;
        RiftHookHandle h = RIFT_INVALID_HANDLE;
        RiftResult r = api_->HookCreate(
            self_, id, target, reinterpret_cast<void*>(detour), &orig, enable_now, &h);
        if (r == RIFT_OK) {
            if (out_original) *out_original = reinterpret_cast<FnPtr>(orig);
            if (out_handle) *out_handle = h;
        }
        return r;
    }

    RiftResult PatchVa(const char* id, uint64_t static_va,
                       std::initializer_list<uint8_t> expected_orig,
                       std::initializer_list<uint8_t> patch_bytes,
                       bool enable_now = true, RiftPatchHandle* out_handle = nullptr) const {
        std::vector<uint8_t> orig(expected_orig);
        std::vector<uint8_t> bytes(patch_bytes);
        if (!orig.empty() && orig.size() != bytes.size()) {
            return RIFT_ERR_INVALID_ARG;
        }
        return api_->PatchCreate(
            self_, id, api_->VaToLive(static_va),
            orig.empty() ? nullptr : orig.data(),
            bytes.data(), bytes.size(), enable_now, out_handle);
    }

    void* AllocStub(size_t size) const { return api_->StubAlloc(self_, size); }
    void FreeStub(void* ptr) const { api_->StubFree(ptr); }

    RiftResult RegisterCommand(const char* name, const char* help, RiftCommandFn cb, void* user_data = nullptr) const {
        return api_->RegisterCommand(self_, name, help, cb, user_data);
    }

    RiftResult RegisterInterface(const char* name, uint32_t version, void* ptr) const {
        return api_->RegisterInterface(self_, name, version, ptr);
    }

    template <typename T>
    T* GetInterface(const char* name, uint32_t min_version = 1) const {
        return reinterpret_cast<T*>(api_->GetInterface(name, min_version));
    }

    RiftEventSubHandle Subscribe(const char* event_name, RiftEventFn cb, void* user_data = nullptr) const {
        return api_->SubscribeEvent(self_, event_name, cb, user_data);
    }

private:
    const RiftLoaderAPI* api_ = nullptr;
    RiftExtHandle self_ = RIFT_INVALID_HANDLE;
};

} // namespace rift
