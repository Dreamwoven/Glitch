#pragma once

#include "rift_sdk.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace riftloader {

// Allocates 16-byte aligned RWX executable stub blocks guaranteed to be within
// +-2GB of an anchor address (so 5-byte E9 rel32 jumps always reach).
class StubAllocator {
public:
    StubAllocator() = default;
    ~StubAllocator();

    StubAllocator(const StubAllocator&) = delete;
    StubAllocator& operator=(const StubAllocator&) = delete;

    void* Alloc(uintptr_t anchor, size_t size, RiftExtHandle owner = RIFT_INVALID_HANDLE);
    void Free(void* ptr);
    void FreeByOwner(RiftExtHandle owner);
    void ReleaseAll();

    struct Stats {
        size_t page_count = 0;
        size_t total_capacity = 0;
        size_t used_bytes = 0;
        size_t live_allocs = 0;
    };
    Stats GetStats() const;

private:
    struct Block {
        size_t offset = 0;
        size_t size = 0;
        RiftExtHandle owner = RIFT_INVALID_HANDLE;
        bool in_use = false;
    };

    struct Page {
        uint8_t* base = nullptr;
        size_t capacity = 0;
        size_t bump = 0;
        std::vector<Block> blocks;
    };

    Page* AllocNewPageNear(uintptr_t anchor, size_t min_size);
    static bool IsWithinRel32(uintptr_t a, uintptr_t b);

    mutable std::mutex mutex_;
    std::vector<Page> pages_;
};

} // namespace riftloader
