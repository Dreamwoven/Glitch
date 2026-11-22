#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace riftloader {

struct X64Insn {
    uint8_t length = 0;           // Total encoded instruction length (0 on decode error)
    bool has_rip_rel = false;     // ModRM mod==00 && rm==101
    uint8_t rip_disp_off = 0;     // Byte offset of 32-bit RIP displacement
    bool is_rel_branch = false;   // E8, E9, EB, 70..7F, 0F 80..8F
    uint8_t branch_disp_off = 0;  // Offset of rel8 or rel32 operand
    uint8_t branch_disp_size = 0; // 1 or 4
    uint8_t branch_opcode = 0;    // Primary opcode (or 0x80..0x8F for 0F 8x)
    bool is_two_byte_jcc = false; // True for 0F 80..8F
    bool is_short_jcc = false;    // True for 70..7F
    bool is_short_jmp = false;    // True for EB
};

// Decodes a single x86-64 instruction at `code` (up to `max_len` bytes, typically 15).
// Returns X64Insn with length == 0 if decoding fails.
X64Insn DecodeX64Insn(const uint8_t* code, size_t max_len = 15);

// Relocates `min_bytes` (rounded up to whole instruction boundaries) from `src_va`
// into `out_trampoline` positioned at `dst_va`, fixing up RIP-relative displacements
// and relative call/jmp/jcc targets. Appends a final jump back to `src_va + stolen_len`.
// Returns stolen_len (> 0) on success, or 0 on failure.
size_t RelocatePrologue(
    const uint8_t* src_bytes,
    uintptr_t src_va,
    size_t min_bytes,
    uintptr_t dst_va,
    std::vector<uint8_t>& out_trampoline);

} // namespace riftloader
