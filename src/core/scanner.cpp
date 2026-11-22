#include "scanner.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cctype>
#include <cstring>

namespace riftloader {

namespace {

int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

Scanner::Scanner(uintptr_t module_base) {
    if (module_base == 0) {
        module_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    }
    module_base_ = module_base;

    if (module_base_) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(module_base_), &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
            mbi.RegionSize >= sizeof(IMAGE_DOS_HEADER)) {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base_);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(module_base_ + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    image_size_ = nt->OptionalHeader.SizeOfImage;
                }
            }
        }
    }
}

uintptr_t Scanner::VaToLive(uint64_t static_va) const {
    if (static_va >= RIFT_STATIC_IMAGE_BASE) {
        return module_base_ + static_cast<uintptr_t>(static_va - RIFT_STATIC_IMAGE_BASE);
    }
    return module_base_ + static_cast<uintptr_t>(static_va);
}

uintptr_t Scanner::RvaToLive(uint32_t rva) const {
    return module_base_ + static_cast<uintptr_t>(rva);
}

uint64_t Scanner::LiveToVa(uintptr_t live_addr) const {
    if (live_addr >= module_base_) {
        return RIFT_STATIC_IMAGE_BASE + static_cast<uint64_t>(live_addr - module_base_);
    }
    return static_cast<uint64_t>(live_addr);
}

bool Scanner::GetSectionRange(const char* section_name, uintptr_t& out_start, size_t& out_size) const {
    if (!module_base_ || !section_name) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base_);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(module_base_ + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        char name_buf[9] = {};
        std::memcpy(name_buf, sec[i].Name, 8);
        if (std::strcmp(name_buf, section_name) == 0) {
            out_start = module_base_ + sec[i].VirtualAddress;
            out_size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            return true;
        }
    }
    return false;
}

bool Scanner::ParsePattern(const std::string& pattern_str, Pattern& out) {
    out.bytes.clear();
    out.mask.clear();

    size_t i = 0;
    const size_t n = pattern_str.size();
    while (i < n) {
        while (i < n && std::isspace(static_cast<unsigned char>(pattern_str[i]))) ++i;
        if (i >= n) break;

        if (pattern_str[i] == '?') {
            ++i;
            if (i < n && pattern_str[i] == '?') ++i;
            out.bytes.push_back(0);
            out.mask.push_back(0);
        } else {
            if (i + 1 >= n) return false;
            int hi = HexNibble(pattern_str[i]);
            int lo = HexNibble(pattern_str[i + 1]);
            if (hi < 0 || lo < 0) return false;
            out.bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
            out.mask.push_back(1);
            i += 2;
        }
    }
    return !out.bytes.empty();
}

bool Scanner::ParseHexBytes(const std::string& hex_str, std::vector<uint8_t>& out) {
    out.clear();
    size_t i = 0;
    const size_t n = hex_str.size();
    while (i < n) {
        while (i < n && (std::isspace(static_cast<unsigned char>(hex_str[i])) || hex_str[i] == ',')) ++i;
        if (i >= n) break;
        // Stop at optional inline comment inside string (e.g. "0F 84 B5 00 00 00 (je ...)")
        if (hex_str[i] == '(' || hex_str[i] == ';') break;
        if (i + 1 >= n) return false;
        int hi = HexNibble(hex_str[i]);
        int lo = HexNibble(hex_str[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        i += 2;
    }
    return !out.empty();
}

std::optional<size_t> Scanner::SearchBuffer(const uint8_t* data, size_t len, const Pattern& pat) {
    if (!data || pat.bytes.empty() || pat.bytes.size() > len) return std::nullopt;
    const size_t plen = pat.bytes.size();
    const size_t limit = len - plen;

    // Find first non-wildcard byte to accelerate scan.
    size_t anchor = 0;
    while (anchor < plen && pat.mask[anchor] == 0) ++anchor;
    if (anchor == plen) return 0; // All wildcards
    const uint8_t anchor_byte = pat.bytes[anchor];

    for (size_t i = 0; i <= limit; ++i) {
        if (data[i + anchor] != anchor_byte) continue;
        bool ok = true;
        for (size_t j = 0; j < plen; ++j) {
            if (pat.mask[j] && data[i + j] != pat.bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok) return i;
    }
    return std::nullopt;
}

RiftResult Scanner::FindPatternInSection(const char* section_name,
                                         const std::string& pattern_str,
                                         uintptr_t& out_addr) const {
    Pattern pat;
    if (!ParsePattern(pattern_str, pat)) return RIFT_ERR_INVALID_ARG;

    uintptr_t start = 0;
    size_t size = 0;
    if (!GetSectionRange(section_name, start, size)) return RIFT_ERR_NOT_FOUND;

    auto off = SearchBuffer(reinterpret_cast<const uint8_t*>(start), size, pat);
    if (!off) return RIFT_ERR_NOT_FOUND;
    out_addr = start + *off;
    return RIFT_OK;
}

RiftResult Scanner::FindPattern(const std::string& pattern_str, uintptr_t& out_addr) const {
    // Prefer .text first (fast path), then fall back to full image.
    if (FindPatternInSection(".text", pattern_str, out_addr) == RIFT_OK) {
        return RIFT_OK;
    }
    Pattern pat;
    if (!ParsePattern(pattern_str, pat)) return RIFT_ERR_INVALID_ARG;
    if (!module_base_ || image_size_ == 0) return RIFT_ERR_NOT_FOUND;

    auto off = SearchBuffer(reinterpret_cast<const uint8_t*>(module_base_), image_size_, pat);
    if (!off) return RIFT_ERR_NOT_FOUND;
    out_addr = module_base_ + *off;
    return RIFT_OK;
}

} // namespace riftloader
