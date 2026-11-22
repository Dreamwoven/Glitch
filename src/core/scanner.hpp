#pragma once

#include "rift_sdk.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace riftloader {

struct Pattern {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask; // 1 = match byte, 0 = wildcard
};

class Scanner {
public:
    explicit Scanner(uintptr_t module_base = 0);

    uintptr_t ModuleBase() const { return module_base_; }
    size_t ImageSize() const { return image_size_; }

    uintptr_t VaToLive(uint64_t static_va) const;
    uintptr_t RvaToLive(uint32_t rva) const;
    uint64_t  LiveToVa(uintptr_t live_addr) const;

    bool GetSectionRange(const char* section_name, uintptr_t& out_start, size_t& out_size) const;

    RiftResult FindPattern(const std::string& pattern_str, uintptr_t& out_addr) const;
    RiftResult FindPatternInSection(const char* section_name, const std::string& pattern_str, uintptr_t& out_addr) const;

    // Pure buffer helpers (directly unit-testable without PE headers).
    static bool ParsePattern(const std::string& pattern_str, Pattern& out);
    static bool ParseHexBytes(const std::string& hex_str, std::vector<uint8_t>& out);
    static std::optional<size_t> SearchBuffer(const uint8_t* data, size_t len, const Pattern& pat);

private:
    uintptr_t module_base_ = 0;
    size_t image_size_ = 0;
};

} // namespace riftloader
