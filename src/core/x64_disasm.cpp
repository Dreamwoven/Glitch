#include "x64_disasm.hpp"

#include <cstring>

namespace riftloader {

namespace {

// Opcode tables for x86-64 instruction length decoding (Intel SDM Vol. 2).
enum OpFlags : uint8_t {
    F_NONE  = 0,
    F_MODRM = 1 << 0,
    F_IMM8  = 1 << 1,
    F_IMM16 = 1 << 2,
    F_IMM32 = 1 << 3,
    F_IMMZ  = 1 << 4, // imm16 if 66h, else imm32
    F_IMMV  = 1 << 5, // imm16 if 66h, imm64 if REX.W, else imm32
    F_REL8  = 1 << 6,
    F_REL32 = 1 << 7,
};

uint8_t GetOneByteFlags(uint8_t op) {
    // 00..3F: ALU ops + PUSH/POP/etc.
    if (op < 0x40) {
        uint8_t low = op & 7;
        if (low <= 3) return F_MODRM;
        if (low == 4) return F_IMM8;
        if (low == 5) return F_IMMZ;
        return F_NONE;
    }
    // 40..4F are REX prefixes (consumed before reaching here).
    // 50..5F: PUSH/POP reg
    if (op >= 0x50 && op <= 0x5F) return F_NONE;
    // 60..6F
    switch (op) {
        case 0x63: return F_MODRM; // MOVSXD
        case 0x68: return F_IMMZ;  // PUSH iz
        case 0x69: return F_MODRM | F_IMMZ; // IMUL Gv,Ev,Iz
        case 0x6A: return F_IMM8;  // PUSH ib
        case 0x6B: return F_MODRM | F_IMM8; // IMUL Gv,Ev,Ib
        case 0x6C: case 0x6D: case 0x6E: case 0x6F: return F_NONE;
    }
    // 70..7F: Jcc rel8
    if (op >= 0x70 && op <= 0x7F) return F_REL8;
    // 80..8F
    switch (op) {
        case 0x80: case 0x82: case 0x83: return F_MODRM | F_IMM8;
        case 0x81: return F_MODRM | F_IMMZ;
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F: return F_MODRM;
    }
    // 90..9F
    if (op >= 0x90 && op <= 0x9F) return F_NONE;
    // A0..AF
    switch (op) {
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            return F_IMMV; // moffset (handled specially as 64-bit addr below)
        case 0xA4: case 0xA5: case 0xA6: case 0xA7:
        case 0xAA: case 0xAB: case 0xAC: case 0xAD:
        case 0xAE: case 0xAF: return F_NONE;
        case 0xA8: return F_IMM8;
        case 0xA9: return F_IMMZ;
    }
    // B0..B7: MOV r8, imm8; B8..BF: MOV r64/32/16, immv
    if (op >= 0xB0 && op <= 0xB7) return F_IMM8;
    if (op >= 0xB8 && op <= 0xBF) return F_IMMV;
    // C0..CF
    switch (op) {
        case 0xC0: case 0xC1: return F_MODRM | F_IMM8;
        case 0xC2: case 0xCA: return F_IMM16;
        case 0xC3: case 0xCB: case 0xCC: case 0xCE: case 0xCF: return F_NONE;
        case 0xC6: return F_MODRM | F_IMM8;
        case 0xC7: return F_MODRM | F_IMMZ;
        case 0xC8: return F_IMM16 | F_IMM8; // ENTER iw, ib
        case 0xC9: return F_NONE;
        case 0xCD: return F_IMM8; // INT ib
    }
    // D0..DF
    if (op >= 0xD0 && op <= 0xD3) return F_MODRM;
    if (op >= 0xD8 && op <= 0xDF) return F_MODRM; // x87 FPU
    if (op == 0xD7) return F_NONE;
    // E0..EF
    switch (op) {
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: return F_REL8;
        case 0xE4: case 0xE5: case 0xE6: case 0xE7: return F_IMM8;
        case 0xE8: case 0xE9: return F_REL32;
        case 0xEB: return F_REL8;
        case 0xEC: case 0xED: case 0xEE: case 0xEF: return F_NONE;
    }
    // F0..FF
    switch (op) {
        case 0xF1: case 0xF4: case 0xF5:
        case 0xF8: case 0xF9: case 0xFA: case 0xFB:
        case 0xFC: case 0xFD: return F_NONE;
        case 0xF6: case 0xF7: return F_MODRM; // TEST reg/0 has extra imm8/immz (handled below)
        case 0xFE: case 0xFF: return F_MODRM;
    }
    return F_NONE;
}

uint8_t GetTwoByteFlags(uint8_t op2) {
    // 0F 00..0F 0F
    switch (op2) {
        case 0x00: case 0x01: case 0x02: case 0x03: case 0x0D: case 0x1F:
            return F_MODRM;
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
            return F_NONE;
    }
    // 0F 10..0F 1F: SSE mov/prefetch/nop
    if (op2 >= 0x10 && op2 <= 0x1F) return F_MODRM;
    // 0F 20..0F 2F: CR/DR/SSE
    if (op2 >= 0x20 && op2 <= 0x2F) return F_MODRM;
    // 0F 30..0F 37: RDMSR/RDTSC/SYSENTER/etc.
    if (op2 >= 0x30 && op2 <= 0x37) return F_NONE;
    // 0F 40..0F 4F: CMOVcc
    if (op2 >= 0x40 && op2 <= 0x4F) return F_MODRM;
    // 0F 50..0F 6F: SSE/MMX
    if (op2 >= 0x50 && op2 <= 0x6F) return F_MODRM;
    // 0F 70..0F 7F
    if (op2 >= 0x70 && op2 <= 0x73) return F_MODRM | F_IMM8;
    if (op2 == 0x77) return F_NONE; // EMMS
    if (op2 >= 0x74 && op2 <= 0x7F) return F_MODRM;
    // 0F 80..0F 8F: Jcc rel32
    if (op2 >= 0x80 && op2 <= 0x8F) return F_REL32;
    // 0F 90..0F 9F: SETcc
    if (op2 >= 0x90 && op2 <= 0x9F) return F_MODRM;
    // 0F A0..0F AF
    switch (op2) {
        case 0xA0: case 0xA1: case 0xA2: case 0xA8: case 0xA9: return F_NONE;
        case 0xA3: case 0xA5: case 0xAB: case 0xAD: case 0xAE: case 0xAF: return F_MODRM;
        case 0xA4: case 0xAC: return F_MODRM | F_IMM8; // SHLD/SHRD imm8
    }
    // 0F B0..0F BF
    switch (op2) {
        case 0xBA: return F_MODRM | F_IMM8; // BT/BTS/BTR/BTC imm8
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5:
        case 0xB6: case 0xB7: case 0xB8: case 0xB9: case 0xBB: case 0xBC:
        case 0xBD: case 0xBE: case 0xBF: return F_MODRM;
    }
    // 0F C0..0F CF
    if (op2 == 0xC0 || op2 == 0xC1 || op2 == 0xC3 || op2 == 0xC7) return F_MODRM;
    if (op2 == 0xC2 || (op2 >= 0xC4 && op2 <= 0xC6)) return F_MODRM | F_IMM8;
    if (op2 >= 0xC8 && op2 <= 0xCF) return F_NONE; // BSWAP
    // 0F D0..0F FF: SSE/SSE2/AVX
    if (op2 >= 0xD0) return F_MODRM;
    return F_MODRM;
}

void EmitInt32(std::vector<uint8_t>& out, int32_t v) {
    uint8_t b[4];
    std::memcpy(b, &v, 4);
    out.insert(out.end(), b, b + 4);
}

void EmitAbsJmp(std::vector<uint8_t>& out, uintptr_t target) {
    // FF 25 00 00 00 00 <u64 target>
    out.push_back(0xFF);
    out.push_back(0x25);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);
    uint8_t b[8];
    uint64_t t = static_cast<uint64_t>(target);
    std::memcpy(b, &t, 8);
    out.insert(out.end(), b, b + 8);
}

bool FitsInt32(int64_t v) {
    return v >= INT32_MIN && v <= INT32_MAX;
}

} // namespace

X64Insn DecodeX64Insn(const uint8_t* code, size_t max_len) {
    X64Insn insn{};
    if (!code || max_len == 0) return insn;
    const size_t limit = max_len < 15 ? max_len : 15;

    size_t i = 0;
    bool has_66 = false;
    bool has_67 = false;
    uint8_t rex = 0;

    // 1. Legacy prefixes
    while (i < limit) {
        uint8_t b = code[i];
        if (b == 0x66) { has_66 = true; ++i; }
        else if (b == 0x67) { has_67 = true; ++i; }
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                 b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                 b == 0x64 || b == 0x65) {
            ++i;
        } else {
            break;
        }
    }
    if (i >= limit) return insn;

    // 2. VEX / EVEX prefixes (AVX / AVX2 / AVX-512)
    bool is_vex = false;
    uint8_t vex_map = 0;
    if (code[i] == 0xC5 && i + 2 < limit) {
        // 2-byte VEX: C5 <byte1> <opcode> (map 0F)
        is_vex = true;
        vex_map = 1;
        i += 2;
    } else if (code[i] == 0xC4 && i + 3 < limit) {
        // 3-byte VEX: C4 <byte1> <byte2> <opcode>
        is_vex = true;
        vex_map = code[i + 1] & 0x1F;
        if (code[i + 2] & 0x80) rex |= 0x48; // VEX.W
        i += 3;
    } else if (code[i] == 0x62 && i + 4 < limit) {
        // 4-byte EVEX
        is_vex = true;
        vex_map = code[i + 1] & 0x03;
        i += 4;
    } else if ((code[i] & 0xF0) == 0x40) {
        // REX prefix
        rex = code[i++];
    }

    if (i >= limit) return insn;

    uint8_t op = code[i++];
    uint8_t flags = F_NONE;
    bool is_f6_f7 = false;
    bool is_moffset = false;

    if (is_vex) {
        if (vex_map == 1) {
            flags = GetTwoByteFlags(op);
        } else if (vex_map == 2) {
            // 0F 38 xx: ModRM, no imm
            flags = F_MODRM;
        } else if (vex_map == 3) {
            // 0F 3A xx: ModRM + imm8
            flags = F_MODRM | F_IMM8;
        } else {
            return insn;
        }
    } else if (op == 0x0F) {
        if (i >= limit) return insn;
        uint8_t op2 = code[i++];
        if (op2 == 0x38) {
            if (i >= limit) return insn;
            ++i; // op3
            flags = F_MODRM;
        } else if (op2 == 0x3A) {
            if (i >= limit) return insn;
            ++i; // op3
            flags = F_MODRM | F_IMM8;
        } else {
            flags = GetTwoByteFlags(op2);
            if (op2 >= 0x80 && op2 <= 0x8F) {
                insn.is_rel_branch = true;
                insn.is_two_byte_jcc = true;
                insn.branch_opcode = op2;
            }
        }
    } else {
        flags = GetOneByteFlags(op);
        if (op == 0xF6 || op == 0xF7) is_f6_f7 = true;
        if (op >= 0xA0 && op <= 0xA3) is_moffset = true;
        if (op == 0xE8 || op == 0xE9 || op == 0xEB || (op >= 0x70 && op <= 0x7F)) {
            insn.is_rel_branch = true;
            insn.branch_opcode = op;
            if (op == 0xEB) insn.is_short_jmp = true;
            if (op >= 0x70 && op <= 0x7F) insn.is_short_jcc = true;
        }
    }

    // 3. ModRM + SIB + Displacement
    if (flags & F_MODRM) {
        if (i >= limit) return insn;
        uint8_t modrm = code[i++];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t reg = (modrm >> 3) & 7;
        uint8_t rm  = modrm & 7;

        // Special case: F6/F7 /0 and /1 (TEST) take an immediate operand.
        if (is_f6_f7 && (reg == 0 || reg == 1)) {
            flags |= (op == 0xF6) ? F_IMM8 : F_IMMZ;
        }

        if (mod != 3) {
            if (rm == 4) {
                // SIB byte present
                if (i >= limit) return insn;
                uint8_t sib = code[i++];
                uint8_t base = sib & 7;
                if (mod == 0 && base == 5) {
                    i += 4; // disp32 (absolute, not RIP-relative)
                }
            } else if (mod == 0 && rm == 5) {
                // [rip + disp32]
                insn.has_rip_rel = true;
                insn.rip_disp_off = static_cast<uint8_t>(i);
                i += 4;
            }

            if (mod == 1) {
                i += 1;
            } else if (mod == 2) {
                i += 4;
            }
        }
    }

    // 4. Immediates & Relative offsets
    if (is_moffset) {
        i += has_67 ? 4 : 8;
    } else {
        if (flags & F_REL8) {
            insn.branch_disp_off = static_cast<uint8_t>(i);
            insn.branch_disp_size = 1;
            i += 1;
        }
        if (flags & F_REL32) {
            insn.branch_disp_off = static_cast<uint8_t>(i);
            insn.branch_disp_size = 4;
            i += 4;
        }
        if (flags & F_IMM16) i += 2;
        if (flags & F_IMM8)  i += 1;
        if (flags & F_IMM32) i += 4;
        if (flags & F_IMMZ)  i += has_66 ? 2 : 4;
        if (flags & F_IMMV) {
            if (rex & 0x08) i += 8;
            else if (has_66) i += 2;
            else i += 4;
        }
    }

    if (i > limit) return X64Insn{};
    insn.length = static_cast<uint8_t>(i);
    return insn;
}

size_t RelocatePrologue(
    const uint8_t* src_bytes,
    uintptr_t src_va,
    size_t min_bytes,
    uintptr_t dst_va,
    std::vector<uint8_t>& out_trampoline) {
    out_trampoline.clear();
    if (!src_bytes || min_bytes == 0) return 0;

    size_t pos = 0;
    while (pos < min_bytes) {
        X64Insn insn = DecodeX64Insn(src_bytes + pos, 15);
        if (insn.length == 0) return 0;

        uintptr_t cur_src = src_va + pos;
        uintptr_t cur_dst = dst_va + out_trampoline.size();

        if (insn.has_rip_rel) {
            int32_t old_disp = 0;
            std::memcpy(&old_disp, src_bytes + pos + insn.rip_disp_off, 4);
            int64_t target = static_cast<int64_t>(cur_src + insn.length) + old_disp;
            int64_t new_disp = target - static_cast<int64_t>(cur_dst + insn.length);
            if (!FitsInt32(new_disp)) return 0;

            size_t base_off = out_trampoline.size();
            out_trampoline.insert(out_trampoline.end(),
                                  src_bytes + pos, src_bytes + pos + insn.length);
            int32_t d32 = static_cast<int32_t>(new_disp);
            std::memcpy(out_trampoline.data() + base_off + insn.rip_disp_off, &d32, 4);
        } else if (insn.is_rel_branch) {
            int64_t disp = 0;
            if (insn.branch_disp_size == 1) {
                int8_t d8 = static_cast<int8_t>(src_bytes[pos + insn.branch_disp_off]);
                disp = d8;
            } else {
                int32_t d32 = 0;
                std::memcpy(&d32, src_bytes + pos + insn.branch_disp_off, 4);
                disp = d32;
            }
            uintptr_t target = static_cast<uintptr_t>(static_cast<int64_t>(cur_src + insn.length) + disp);

            if (insn.is_short_jmp) {
                // Promote EB rel8 -> E9 rel32 (or abs jmp if > 2GB)
                int64_t rel = static_cast<int64_t>(target) - static_cast<int64_t>(cur_dst + 5);
                if (FitsInt32(rel)) {
                    out_trampoline.push_back(0xE9);
                    EmitInt32(out_trampoline, static_cast<int32_t>(rel));
                } else {
                    EmitAbsJmp(out_trampoline, target);
                }
            } else if (insn.is_short_jcc) {
                // Promote 7x rel8 -> 0F 8x rel32
                uint8_t cc = insn.branch_opcode & 0x0F;
                int64_t rel = static_cast<int64_t>(target) - static_cast<int64_t>(cur_dst + 6);
                if (!FitsInt32(rel)) return 0;
                out_trampoline.push_back(0x0F);
                out_trampoline.push_back(static_cast<uint8_t>(0x80 | cc));
                EmitInt32(out_trampoline, static_cast<int32_t>(rel));
            } else if (insn.is_two_byte_jcc) {
                int64_t rel = static_cast<int64_t>(target) - static_cast<int64_t>(cur_dst + 6);
                if (!FitsInt32(rel)) return 0;
                out_trampoline.push_back(0x0F);
                out_trampoline.push_back(insn.branch_opcode);
                EmitInt32(out_trampoline, static_cast<int32_t>(rel));
            } else if (insn.branch_opcode == 0xE8 || insn.branch_opcode == 0xE9) {
                int64_t rel = static_cast<int64_t>(target) - static_cast<int64_t>(cur_dst + 5);
                if (FitsInt32(rel)) {
                    out_trampoline.push_back(insn.branch_opcode);
                    EmitInt32(out_trampoline, static_cast<int32_t>(rel));
                } else if (insn.branch_opcode == 0xE9) {
                    EmitAbsJmp(out_trampoline, target);
                } else {
                    // Executable stub guarantees E8 call fits rel32; fail safely if somehow out of range.
                    return 0;
                }
            } else {
                // LOOP/JRCXZ rel8 inside prologue - cannot safely relocate far.
                return 0;
            }
        } else {
            out_trampoline.insert(out_trampoline.end(),
                                  src_bytes + pos, src_bytes + pos + insn.length);
        }

        pos += insn.length;
    }

    // Emit jump back to src_va + pos.
    uintptr_t back_va = src_va + pos;
    uintptr_t jmp_at = dst_va + out_trampoline.size();
    int64_t back_rel = static_cast<int64_t>(back_va) - static_cast<int64_t>(jmp_at + 5);
    if (FitsInt32(back_rel)) {
        out_trampoline.push_back(0xE9);
        EmitInt32(out_trampoline, static_cast<int32_t>(back_rel));
    } else {
        EmitAbsJmp(out_trampoline, back_va);
    }
    return pos;
}

} // namespace riftloader
