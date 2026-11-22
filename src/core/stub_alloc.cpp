#include "stub_alloc.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <cstring>

namespace riftloader {

namespace {
constexpr size_t kAlign = 16;
constexpr size_t kDefaultPageSize = 64 * 1024;
// Stay comfortably inside signed 32-bit range (+-2GB = 0x7FFF0000) with margin.
constexpr uintptr_t kMaxRel32Distance = 0x78000000ULL;

size_t AlignUp(size_t v, size_t a) {
    return (v + a - 1) & ~(a - 1);
}
} // namespace

StubAllocator::~StubAllocator() {
    ReleaseAll();
}

bool StubAllocator::IsWithinRel32(uintptr_t a, uintptr_t b) {
    uintptr_t diff = (a >= b) ? (a - b) : (b - a);
    return diff <= kMaxRel32Distance;
}

StubAllocator::Page* StubAllocator::AllocNewPageNear(uintptr_t anchor, size_t min_size) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    const uintptr_t min_addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t max_addr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    const size_t alloc_size = AlignUp((std::max)(min_size, kDefaultPageSize), gran);

    const uintptr_t low_bound = (anchor > kMaxRel32Distance + min_addr)
                                    ? (anchor - kMaxRel32Distance)
                                    : min_addr;
    const uintptr_t high_bound = (anchor + kMaxRel32Distance < max_addr)
                                     ? (anchor + kMaxRel32Distance)
                                     : max_addr;

    auto try_range = [&](uintptr_t start, uintptr_t end, bool search_down) -> uint8_t* {
        if (!search_down) {
            uintptr_t cur = AlignUp(start, gran);
            while (cur + alloc_size <= end) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi)) == 0) break;
                if (mbi.State == MEM_FREE) {
                    uintptr_t region_start = AlignUp(reinterpret_cast<uintptr_t>(mbi.BaseAddress), gran);
                    uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                    if (region_start < cur) region_start = cur;
                    if (region_start + alloc_size <= region_end && region_start + alloc_size <= end) {
                        void* p = VirtualAlloc(reinterpret_cast<void*>(region_start), alloc_size,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (p) return static_cast<uint8_t*>(p);
                    }
                }
                uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= cur) break;
                cur = AlignUp(next, gran);
            }
        } else {
            uintptr_t cur = (end >= alloc_size) ? ((end - alloc_size) & ~(gran - 1)) : 0;
            while (cur >= start && cur >= min_addr) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi)) == 0) break;
                if (mbi.State == MEM_FREE) {
                    uintptr_t region_start = AlignUp(reinterpret_cast<uintptr_t>(mbi.BaseAddress), gran);
                    uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                    uintptr_t cand = (region_end >= alloc_size) ? ((region_end - alloc_size) & ~(gran - 1)) : 0;
                    if (cand > cur) cand = cur;
                    if (cand >= region_start && cand >= start && cand + alloc_size <= region_end) {
                        void* p = VirtualAlloc(reinterpret_cast<void*>(cand), alloc_size,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (p) return static_cast<uint8_t*>(p);
                    }
                }
                uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                if (base <= gran || base <= start) break;
                cur = (base - gran) & ~(gran - 1);
            }
        }
        return nullptr;
    };

    // Search upward past the module first, then downward below it.
    uint8_t* mem = try_range(anchor, high_bound, false);
    if (!mem && anchor > low_bound) {
        mem = try_range(low_bound, anchor, true);
    }
    if (!mem) return nullptr;

    // Fill with INT3 so accidental fall-through traps cleanly.
    std::memset(mem, 0xCC, alloc_size);

    Page page;
    page.base = mem;
    page.capacity = alloc_size;
    page.bump = 0;
    pages_.push_back(std::move(page));
    return &pages_.back();
}

void* StubAllocator::Alloc(uintptr_t anchor, size_t size, RiftExtHandle owner) {
    if (size == 0) return nullptr;
    const size_t aligned = AlignUp(size, kAlign);

    std::lock_guard<std::mutex> lock(mutex_);

    // 1. Reuse freed block in a nearby page if one fits.
    for (auto& page : pages_) {
        uintptr_t paddr = reinterpret_cast<uintptr_t>(page.base);
        if (!IsWithinRel32(anchor, paddr) || !IsWithinRel32(anchor, paddr + page.capacity)) {
            continue;
        }
        for (auto& blk : page.blocks) {
            if (!blk.in_use && blk.size >= aligned) {
                blk.in_use = true;
                blk.owner = owner;
                std::memset(page.base + blk.offset, 0xCC, blk.size);
                return page.base + blk.offset;
            }
        }
        if (page.bump + aligned <= page.capacity) {
            Block blk;
            blk.offset = page.bump;
            blk.size = aligned;
            blk.owner = owner;
            blk.in_use = true;
            page.bump += aligned;
            page.blocks.push_back(blk);
            return page.base + blk.offset;
        }
    }

    // 2. Allocate a new page within +-2GB of anchor.
    Page* page = AllocNewPageNear(anchor, aligned);
    if (!page) return nullptr;

    Block blk;
    blk.offset = 0;
    blk.size = aligned;
    blk.owner = owner;
    blk.in_use = true;
    page->bump = aligned;
    page->blocks.push_back(blk);
    return page->base;
}

void StubAllocator::Free(void* ptr) {
    if (!ptr) return;
    std::lock_guard<std::mutex> lock(mutex_);
    auto* p = static_cast<uint8_t*>(ptr);
    for (auto& page : pages_) {
        if (p >= page.base && p < page.base + page.capacity) {
            size_t off = static_cast<size_t>(p - page.base);
            for (auto& blk : page.blocks) {
                if (blk.offset == off && blk.in_use) {
                    blk.in_use = false;
                    blk.owner = RIFT_INVALID_HANDLE;
                    std::memset(page.base + blk.offset, 0xCC, blk.size);
                    FlushInstructionCache(GetCurrentProcess(), page.base + blk.offset, blk.size);
                    return;
                }
            }
        }
    }
}

void StubAllocator::FreeByOwner(RiftExtHandle owner) {
    if (owner == RIFT_INVALID_HANDLE) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& page : pages_) {
        for (auto& blk : page.blocks) {
            if (blk.in_use && blk.owner == owner) {
                blk.in_use = false;
                blk.owner = RIFT_INVALID_HANDLE;
                std::memset(page.base + blk.offset, 0xCC, blk.size);
                FlushInstructionCache(GetCurrentProcess(), page.base + blk.offset, blk.size);
            }
        }
    }
}

void StubAllocator::ReleaseAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& page : pages_) {
        if (page.base) {
            VirtualFree(page.base, 0, MEM_RELEASE);
            page.base = nullptr;
        }
    }
    pages_.clear();
}

StubAllocator::Stats StubAllocator::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats s;
    s.page_count = pages_.size();
    for (const auto& page : pages_) {
        s.total_capacity += page.capacity;
        for (const auto& blk : page.blocks) {
            if (blk.in_use) {
                s.used_bytes += blk.size;
                ++s.live_allocs;
            }
        }
    }
    return s;
}

} // namespace riftloader
