#include "stub_alloc.hpp"
#include "config.hpp"
#include "extension_manager.hpp"
#include "hook_engine.hpp"
#include "loader_main.hpp"
#include "memory_patch.hpp"
#include "patch_manager.hpp"
#include "rivet_parser.hpp"
#include "scanner.hpp"
#include "x64_disasm.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define EXPECT_TRUE(cond) do { \
    if (!(cond)) { \
        std::cerr << "  [FAIL] " << __FILE__ << ":" << __LINE__ << " EXPECT_TRUE(" #cond ")\n"; \
        ++g_fail; \
        return; \
    } \
} while (0)

#define EXPECT_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (!(_a == _b)) { \
        std::cerr << "  [FAIL] " << __FILE__ << ":" << __LINE__ << " EXPECT_EQ(" #a ", " #b ") got " \
                  << _a << " vs " << _b << "\n"; \
        ++g_fail; \
        return; \
    } \
} while (0)

void RunTest(const char* name, void (*fn)()) {
    std::cout << "[RUN ] " << name << std::endl;
    int before = g_fail;
    fn();
    if (g_fail == before) {
        ++g_pass;
        std::cout << "[PASS] " << name << std::endl;
    } else {
        std::cout << "[FAIL] " << name << std::endl;
    }
}

// ---- Test 1: Rivet (.rvt) Parser ----
void TestRivetParser() {
    const std::string doc =
        "// Comment line\n"
        "# Hash comment\n"
        "name.\"test_mod\"\n"
        "enabled.true\n"
        "count:42\n"
        "hex_va.\"0x1410C5B57\"\n"
        "escaped.\"line1\\nline2\\t\\\"ok\\\"\"\n"
        "items.arr;\n"
        "\t.obj;\n"
        "\t\tid.\"first\"\n"
        "\t\tval:100\n"
        "\t.obj;\n"
        "\t\tid.\"second\"\n"
        "\t\tflag.false\n"
        "tags.arr;\n"
        "\t.\"alpha\"\n"
        "\t.\"beta\"\n";

    auto res = riftloader::RivetParser::Parse(doc);
    EXPECT_TRUE(res.Ok());
    EXPECT_EQ(res.root->GetString("name"), "test_mod");
    EXPECT_EQ(res.root->GetBool("enabled", false), true);
    EXPECT_TRUE(res.root->GetInt("count").has_value());
    EXPECT_EQ(*res.root->GetInt("count"), 42);
    EXPECT_TRUE(res.root->GetUInt("hex_va").has_value());
    EXPECT_EQ(*res.root->GetUInt("hex_va"), 0x1410C5B57ULL);
    EXPECT_EQ(res.root->GetString("escaped"), "line1\nline2\t\"ok\"");

    const auto* items = res.root->Get("items");
    EXPECT_TRUE(items != nullptr);
    EXPECT_EQ(items->ordered_children.size(), 2u);
    EXPECT_EQ(items->GetString("0.id"), "first");
    EXPECT_EQ(*items->GetInt("0.val"), 100);
    EXPECT_EQ(items->GetString("1.id"), "second");
    EXPECT_EQ(items->GetBool("1.flag", true), false);

    const auto* tags = res.root->Get("tags");
    EXPECT_TRUE(tags != nullptr);
    EXPECT_EQ(tags->ordered_children.size(), 2u);
    EXPECT_EQ(tags->GetString("0"), "alpha");
    EXPECT_EQ(tags->GetString("1"), "beta");

    // Error case: child under non-parent node (missing ';')
    auto bad = riftloader::RivetParser::Parse("leaf.\"val\"\n\tchild.\"oops\"\n");
    EXPECT_TRUE(!bad.Ok());

    // Smoke-test shipped .rvt manifests in Loader/
    std::filesystem::path repo(RIFT_TEST_REPO_ROOT);
    auto ex_man = riftloader::RivetParser::ParseFile(
        (repo / "Loader" / "examples" / "patches" / "example_p5_terrain_shadow.rvt").string());
    EXPECT_TRUE(ex_man.Ok());
    EXPECT_EQ(ex_man.root->GetString("name"), "P5_terrain_shadowkill");
    EXPECT_EQ(ex_man.root->GetBool("enabled", true), false);

    // Parse every ported patch manifest in Loader/patches/
    size_t ported_count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(repo / "Loader" / "patches")) {
        if (entry.is_regular_file() && entry.path().extension() == ".rvt") {
            auto pm = riftloader::RivetParser::ParseFile(entry.path().string());
            EXPECT_TRUE(pm.Ok());
            EXPECT_TRUE(!pm.root->GetString("name").empty());
            EXPECT_TRUE(pm.root->Get("patches") != nullptr);
            ++ported_count;
        }
    }
    EXPECT_EQ(ported_count, 15u);
}

// ---- Test 2: Scanner Pattern & Hex Parsing ----
void TestScanner() {
    riftloader::Pattern pat;
    EXPECT_TRUE(riftloader::Scanner::ParsePattern("48 8D ?? 30 ? 01 00", pat));
    EXPECT_EQ(pat.bytes.size(), 7u);
    EXPECT_EQ(pat.mask[2], 0);
    EXPECT_EQ(pat.mask[4], 0);
    EXPECT_EQ(pat.bytes[0], 0x48);

    const uint8_t hay[] = {0x90, 0x90, 0x48, 0x8D, 0xAA, 0x30, 0xBB, 0x01, 0x00, 0xC3};
    auto hit = riftloader::Scanner::SearchBuffer(hay, sizeof(hay), pat);
    EXPECT_TRUE(hit.has_value());
    EXPECT_EQ(*hit, 2u);

    std::vector<uint8_t> hex;
    EXPECT_TRUE(riftloader::Scanner::ParseHexBytes("0F 84 B5 00 00 00 (je 0x1410c5cd0)", hex));
    EXPECT_EQ(hex.size(), 6u);
    EXPECT_EQ(hex[0], 0x0F);
    EXPECT_EQ(hex[5], 0x00);

    // ASLR VA <-> Live conversion
    riftloader::Scanner sc(0x7FF610000000ULL);
    EXPECT_EQ(sc.VaToLive(0x1410C5B57ULL), 0x7FF6110C5B57ULL);
    EXPECT_EQ(sc.LiveToVa(0x7FF6110C5B57ULL), 0x1410C5B57ULL);
}

// ---- Test 3: x64 Disassembler & Prologue Relocator ----
void TestX64DisasmAndReloc() {
    // WinMainCRTStartup bytes from Binaries/RiftApart.exe @ 0x142d21018
    const uint8_t crt_ep[] = {
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28 (4 B)
        0xE8, 0x0B, 0x2D, 0x00, 0x00,       // call +0x2d0b  (5 B)
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28 (4 B)
        0xE9, 0xF6, 0xFD, 0xFF, 0xFF        // jmp -0x20a    (5 B)
    };
    auto i0 = riftloader::DecodeX64Insn(crt_ep, sizeof(crt_ep));
    EXPECT_EQ(i0.length, 4);
    auto i1 = riftloader::DecodeX64Insn(crt_ep + 4, sizeof(crt_ep) - 4);
    EXPECT_EQ(i1.length, 5);
    EXPECT_TRUE(i1.is_rel_branch);
    EXPECT_EQ(i1.branch_opcode, 0xE8);

    // RIP-relative mov eax, [rip + 0x1000] (6 bytes)
    const uint8_t rip_mov[] = {0x8B, 0x05, 0x00, 0x10, 0x00, 0x00, 0xC3};
    auto ir = riftloader::DecodeX64Insn(rip_mov, sizeof(rip_mov));
    EXPECT_EQ(ir.length, 6);
    EXPECT_TRUE(ir.has_rip_rel);
    EXPECT_EQ(ir.rip_disp_off, 2);

    // Relocate from 0x140010000 to 0x140020000 (+0x10000 shift)
    std::vector<uint8_t> tramp;
    size_t stolen = riftloader::RelocatePrologue(rip_mov, 0x140010000ULL, 5, 0x140020000ULL, tramp);
    EXPECT_EQ(stolen, 6u);
    EXPECT_EQ(tramp.size(), 11u); // 6 B relocated mov + 5 B jmp back
    int32_t new_disp = 0;
    std::memcpy(&new_disp, tramp.data() + 2, 4);
    // Original target: 0x140010006 + 0x1000 = 0x140011006
    // Relocated rip:   0x140020006 -> expected disp = 0x140011006 - 0x140020006 = -0xF000
    EXPECT_EQ(new_disp, -0xF000);
}

// ---- Test 4: Executable Stub Allocator ----
void TestStubAllocator() {
    riftloader::StubAllocator alloc;
    uintptr_t anchor = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    void* c1 = alloc.Alloc(anchor, 64, 1);
    void* c2 = alloc.Alloc(anchor, 128, 1);
    void* c3 = alloc.Alloc(anchor, 32, 2);
    EXPECT_TRUE(c1 != nullptr && c2 != nullptr && c3 != nullptr);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(c1) % 16, 0u);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(c2) % 16, 0u);

    auto diff = [](uintptr_t a, uintptr_t b) { return a >= b ? a - b : b - a; };
    EXPECT_TRUE(diff(reinterpret_cast<uintptr_t>(c1), anchor) < 0x7FFF0000ULL);
    EXPECT_TRUE(diff(reinterpret_cast<uintptr_t>(c3), anchor) < 0x7FFF0000ULL);

    EXPECT_EQ(alloc.GetStats().live_allocs, 3u);
    alloc.FreeByOwner(1);
    EXPECT_EQ(alloc.GetStats().live_allocs, 1u);
    alloc.Free(c3);
    EXPECT_EQ(alloc.GetStats().live_allocs, 0u);
}

// ---- Test 5: MemoryPatcher (verify, conflict, toggle, rollback) ----
void TestMemoryPatcher() {
    riftloader::MemoryPatcher patcher;
    uint8_t buf[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    const uint8_t orig[4] = {0x10, 0x20, 0x30, 0x40};
    const uint8_t bad_orig[4] = {0x99, 0x20, 0x30, 0x40};
    const uint8_t patched[4] = {0xAA, 0xBB, 0xCC, 0xDD};

    // Wrong original bytes must be rejected
    RiftPatchHandle h_bad = RIFT_INVALID_HANDLE;
    EXPECT_EQ(patcher.Create(1, "bad", reinterpret_cast<uintptr_t>(buf), bad_orig, patched, 4, true, &h_bad),
              RIFT_ERR_BYTES_MISMATCH);

    // Valid patch applies cleanly
    RiftPatchHandle h1 = RIFT_INVALID_HANDLE;
    EXPECT_EQ(patcher.Create(1, "p1", reinterpret_cast<uintptr_t>(buf), orig, patched, 4, true, &h1),
              RIFT_OK);
    EXPECT_EQ(buf[0], 0xAA);
    EXPECT_EQ(buf[3], 0xDD);

    // Overlapping patch must fail with RIFT_ERR_CONFLICT
    RiftPatchHandle h_overlap = RIFT_INVALID_HANDLE;
    EXPECT_EQ(patcher.Create(2, "overlap", reinterpret_cast<uintptr_t>(buf + 2), nullptr, patched, 4, true, &h_overlap),
              RIFT_ERR_CONFLICT);

    // Disable restores original bytes bit-for-bit
    EXPECT_EQ(patcher.Disable(h1), RIFT_OK);
    EXPECT_EQ(std::memcmp(buf, orig, 4), 0);

    // Re-enable works, and RemoveByOwner restores + deletes
    EXPECT_EQ(patcher.Enable(h1), RIFT_OK);
    EXPECT_EQ(buf[0], 0xAA);
    patcher.RemoveByOwner(1);
    EXPECT_EQ(std::memcmp(buf, orig, 4), 0);
    EXPECT_EQ(patcher.List().size(), 0u);
}

// ---- Test 6: Live x64 Function Hook + RIP-Relative Trampoline ----
volatile int g_rip_secret = 1000;

__declspec(noinline) int TargetCompute(int a, int b) {
    // Forces a RIP-relative read of g_rip_secret early in the function!
    int base = g_rip_secret;
    return base + a * 3 + b;
}

using ComputeFn = int (*)(int, int);
ComputeFn g_orig_compute = nullptr;
int g_hook_hits = 0;

int DetourCompute(int a, int b) {
    ++g_hook_hits;
    return g_orig_compute(a, b) + 77;
}

void TestLiveFunctionHook() {
    riftloader::StubAllocator stubs;
    riftloader::HookEngine hooks(stubs);

    EXPECT_EQ(TargetCompute(10, 5), 1035);

    RiftHookHandle h = RIFT_INVALID_HANDLE;
    void* orig_ptr = nullptr;
    RiftResult r = hooks.Create(1, "compute_hook",
                                reinterpret_cast<void*>(&TargetCompute),
                                reinterpret_cast<void*>(&DetourCompute),
                                &orig_ptr, true, &h);
    EXPECT_EQ(r, RIFT_OK);
    g_orig_compute = reinterpret_cast<ComputeFn>(orig_ptr);

    g_hook_hits = 0;
    EXPECT_EQ(TargetCompute(10, 5), 1112); // 1035 + 77
    EXPECT_EQ(g_hook_hits, 1);

    // Disable hook -> restores exact original behavior
    EXPECT_EQ(hooks.Disable(h), RIFT_OK);
    EXPECT_EQ(TargetCompute(10, 5), 1035);
    EXPECT_EQ(g_hook_hits, 1);

    // Re-enable -> detour active again
    EXPECT_EQ(hooks.Enable(h), RIFT_OK);
    EXPECT_EQ(TargetCompute(10, 5), 1112);
    EXPECT_EQ(g_hook_hits, 2);

    // Owner cleanup removes hook completely
    hooks.RemoveByOwner(1);
    EXPECT_EQ(TargetCompute(10, 5), 1035);
    EXPECT_EQ(hooks.List().size(), 0u);
}

// ---- Test 7: Declarative .rvt Patch Manager (direct + stub_bytes) ----
void TestRvtPatchManager() {
    // Allocate a tiny RWX test function:
    //   mov eax, 10   ; B8 0A 00 00 00
    //   nop           ; 90
    //   ret           ; C3
    uint8_t* fn_mem = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    EXPECT_TRUE(fn_mem != nullptr);

    const uint8_t orig_code[] = {0xB8, 0x0A, 0x00, 0x00, 0x00, 0x90, 0xC3};
    std::memcpy(fn_mem, orig_code, sizeof(orig_code));
    FlushInstructionCache(GetCurrentProcess(), fn_mem, sizeof(orig_code));

    using RetIntFn = int (*)(void);
    auto fn = reinterpret_cast<RetIntFn>(fn_mem);
    EXPECT_EQ(fn(), 10);

    // Write a temporary .rvt manifest with a declarative stub detour returning 99!
    namespace fs = std::filesystem;
    fs::path tmp_dir = fs::temp_directory_path() / "glitch_test_patches";
    fs::create_directories(tmp_dir);
    fs::path rvt_path = tmp_dir / "test_stub.rvt";
    {
        std::ofstream f(rvt_path, std::ios::binary);
        f << "name.\"test_stub_ret99\"\n"
          << "enabled.true\n"
          << "patches.arr;\n"
          << "\t.obj;\n"
          << "\t\tid.\"ret99\"\n"
          << "\t\tlive_addr.\"0x" << std::hex << reinterpret_cast<uintptr_t>(fn_mem) << std::dec << "\"\n"
          << "\t\torig.\"B8 0A 00 00 00\"\n"
          << "\t\t// stub sets eax = 99, then PatchManager appends jmp back to fn_mem+5 (nop; ret)\n"
          << "\t\tstub_bytes.\"B8 63 00 00 00\"\n";
    }

    riftloader::Logger logger;
    riftloader::Scanner scanner;
    riftloader::MemoryPatcher patcher;
    riftloader::StubAllocator stubs;
    riftloader::PatchManager pm(logger, scanner, patcher, stubs);

    pm.LoadDirectory(tmp_dir.string(), {});
    EXPECT_EQ(pm.List().size(), 1u);
    EXPECT_TRUE(pm.List()[0].enabled);
    EXPECT_EQ(fn(), 99);

    // Toggle off -> back to 10!
    std::string msg;
    EXPECT_TRUE(pm.DisableByName("test_stub_ret99", msg));
    EXPECT_EQ(fn(), 10);

    // Toggle back on -> 99!
    EXPECT_TRUE(pm.ToggleByName("test_stub_ret99", msg));
    EXPECT_EQ(fn(), 99);

    // Now test stub_fixups + disabled overlapping patch hot-swap!
    // Allocate a second test global adjacent to fn_mem so it is guaranteed within +-2GB of stub.
    int32_t* shared_val = reinterpret_cast<int32_t*>(fn_mem + 0x100);
    *shared_val = 4242;

    // Write a conflicting patch at the SAME live_addr (disabled initially) that reads *shared_val via RIP-rel fixup
    // and uses stub_auto_return.false with its own explicit E9 back fixup!
    //   8B 05 <disp32>  mov eax, [rip + disp32]   (off=2 -> shared_val)
    //   E9 <rel32>      jmp fn_mem + 5            (off=7 -> fn_mem + 5)
    fs::path rvt_alt = tmp_dir / "test_stub_fixup.rvt";
    {
        std::ofstream f(rvt_alt, std::ios::binary);
        f << "name.\"test_stub_fixup_4242\"\n"
          << "enabled.false\n"
          << "patches.arr;\n"
          << "\t.obj;\n"
          << "\t\tid.\"read_global\"\n"
          << "\t\tlive_addr.\"0x" << std::hex << reinterpret_cast<uintptr_t>(fn_mem) << std::dec << "\"\n"
          << "\t\torig.\"B8 0A 00 00 00\"\n"
          << "\t\tstub_auto_return.false\n"
          << "\t\tstub_bytes.\"8B 05 00 00 00 00 E9 00 00 00 00\"\n"
          << "\t\tstub_fixups.arr;\n"
          << "\t\t\t.obj;\n"
          << "\t\t\t\toff:2\n"
          << "\t\t\t\ttarget_live_addr.\"0x" << std::hex << reinterpret_cast<uintptr_t>(shared_val) << std::dec << "\"\n"
          << "\t\t\t.obj;\n"
          << "\t\t\t\toff:7\n"
          << "\t\t\t\ttarget_live_addr.\"0x" << std::hex << reinterpret_cast<uintptr_t>(fn_mem + 5) << std::dec << "\"\n";
    }

    EXPECT_TRUE(pm.LoadManifestFile(rvt_alt.string(), {}));
    EXPECT_EQ(pm.List().size(), 2u);
    EXPECT_EQ(fn(), 99);

    // Enabling alt while ret99 is still active must fail cleanly with conflict!
    EXPECT_TRUE(!pm.EnableByName("test_stub_fixup_4242", msg));
    EXPECT_EQ(fn(), 99);

    // Disable ret99 -> hot-swap to fixup_4242 -> executes RIP-rel load from *shared_val!
    EXPECT_TRUE(pm.DisableByName("test_stub_ret99", msg));
    EXPECT_EQ(fn(), 10);
    EXPECT_TRUE(pm.EnableByName("test_stub_fixup_4242", msg));
    EXPECT_EQ(fn(), 4242);
    *shared_val = 7777;
    EXPECT_EQ(fn(), 7777);

    pm.UnloadAll();
    EXPECT_EQ(fn(), 10);

    VirtualFree(fn_mem, 0, MEM_RELEASE);
    std::error_code ec;
    fs::remove_all(tmp_dir, ec);
}

// ---- Test 8: Full LoaderRuntime + hello_ext.dll Extension Lifecycle ----
void TestExtensionEndToEnd() {
    namespace fs = std::filesystem;
    fs::path tmp_game = fs::temp_directory_path() / "riftloader_test_game";
    std::error_code ec;
    fs::remove_all(tmp_game, ec);
    fs::create_directories(tmp_game / "glitch" / "extensions", ec);
    fs::create_directories(tmp_game / "glitch" / "patches", ec);

    // Write config with console disabled for headless test execution.
    {
        std::ofstream cfg(tmp_game / "glitch" / "config.rvt", std::ios::binary);
        cfg << "console.false\n"
            << "log_level.\"debug\"\n"
            << "log_file.\"glitch/test.log\"\n"
            << "patches_dir.\"glitch/patches\"\n"
            << "extensions_dir.\"glitch/extensions\"\n";
    }

    // Copy compiled hello_ext.dll into extensions/.
    fs::copy_file(RIFT_TEST_HELLO_EXT_DLL,
                  tmp_game / "glitch" / "extensions" / "hello_ext.dll",
                  fs::copy_options::overwrite_existing);

    riftloader::LoaderRuntime runtime;
    EXPECT_TRUE(runtime.Initialize(tmp_game.string(), 0, false));

    auto exts = runtime.Extensions().List();
    EXPECT_EQ(exts.size(), 1u);
    EXPECT_EQ(exts[0].name, "hello_ext");

    // Query shared interface exposed by hello_ext!
    struct IHelloService {
        int (*GetPingCount)(void);
        int (*AddNumbers)(int a, int b);
    };
    auto* svc = static_cast<IHelloService*>(runtime.Api().GetInterface("IHelloService", 1));
    EXPECT_TRUE(svc != nullptr);
    EXPECT_EQ(svc->AddNumbers(20, 22), 42);
    EXPECT_EQ(svc->GetPingCount(), 0);

    // Execute extension-registered console command!
    EXPECT_TRUE(runtime.GetConsole().ExecuteLine("hello world"));
    EXPECT_EQ(svc->GetPingCount(), 1);

    // Execute built-in status command too
    EXPECT_TRUE(runtime.GetConsole().ExecuteLine("status"));

    // Live unload -> command and shared interface must disappear automatically!
    std::string msg;
    EXPECT_TRUE(runtime.Extensions().UnloadByName("hello_ext", msg));
    EXPECT_EQ(runtime.Extensions().List().size(), 0u);
    EXPECT_TRUE(runtime.Api().GetInterface("IHelloService", 1) == nullptr);
    EXPECT_TRUE(!runtime.GetConsole().ExecuteLine("hello"));

    // Live load back -> fresh state!
    EXPECT_TRUE(runtime.Extensions().LoadExtension(
        (tmp_game / "glitch" / "extensions" / "hello_ext.dll").string(), msg));
    svc = static_cast<IHelloService*>(runtime.Api().GetInterface("IHelloService", 1));
    EXPECT_TRUE(svc != nullptr);
    EXPECT_EQ(svc->GetPingCount(), 0);

    runtime.Shutdown();
    fs::remove_all(tmp_game, ec);
}

// ---- Test 9: PatchManager required_manifests (topo order, gating, cascade, cycle) ----
void TestRequiredManifests() {
    namespace fs = std::filesystem;
    fs::path tmp_dir = fs::temp_directory_path() / "riftloader_test_req_manifests";
    std::error_code ec;
    fs::remove_all(tmp_dir, ec);
    fs::create_directories(tmp_dir, ec);

    // Allocate 64-byte writable buffer for 5 distinct 1-byte patch sites.
    uint8_t* mem = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    EXPECT_TRUE(mem != nullptr);
    mem[0] = 0x10; // dependent
    mem[1] = 0x20; // base
    mem[2] = 0x30; // missing_dep
    mem[3] = 0x40; // cyc_a
    mem[4] = 0x50; // cyc_b

    auto write_rvt = [&](const std::string& filename, const std::string& name,
                         uint8_t* addr, uint8_t orig_b, uint8_t new_b,
                         const std::vector<std::string>& reqs) {
        std::ofstream f(tmp_dir / filename, std::ios::binary);
        f << "name.\"" << name << "\"\n"
          << "enabled.true\n";
        if (!reqs.empty()) {
            f << "required_manifests.arr;\n";
            for (const auto& r : reqs) f << "\t.\"" << r << "\"\n";
        }
        char orig_hex[8], new_hex[8];
        std::snprintf(orig_hex, sizeof(orig_hex), "%02X", orig_b);
        std::snprintf(new_hex, sizeof(new_hex), "%02X", new_b);
        f << "patches.arr;\n"
          << "\t.obj;\n"
          << "\t\tid.\"b\"\n"
          << "\t\tlive_addr.\"0x" << std::hex << reinterpret_cast<uintptr_t>(addr) << std::dec << "\"\n"
          << "\t\torig.\"" << orig_hex << "\"\n"
          << "\t\tbytes.\"" << new_hex << "\"\n";
    };

    // 01_dependent sorts BEFORE 02_base, mirroring 13_k1_dx12_async_res -> 14_k1_dx12_async_res_fix.
    write_rvt("01_dependent.rvt", "dependent", mem + 0, 0x10, 0x11, {"base"});
    write_rvt("02_base.rvt", "base", mem + 1, 0x20, 0x22, {});
    write_rvt("03_missing_dep.rvt", "missing_dep", mem + 2, 0x30, 0x33, {"does_not_exist"});
    write_rvt("04_cyc_a.rvt", "cyc_a", mem + 3, 0x40, 0x44, {"cyc_b"});
    write_rvt("05_cyc_b.rvt", "cyc_b", mem + 4, 0x50, 0x55, {"cyc_a"});

    riftloader::Logger logger;
    riftloader::Scanner scanner;
    riftloader::MemoryPatcher patcher;
    riftloader::StubAllocator stubs;
    riftloader::PatchManager pm(logger, scanner, patcher, stubs);

    // 1) Normal load: base + dependent both enabled; missing_dep + cycle pair remain disabled.
    pm.LoadDirectory(tmp_dir.string(), {});
    EXPECT_EQ(mem[0], 0x11);
    EXPECT_EQ(mem[1], 0x22);
    EXPECT_EQ(mem[2], 0x30);
    EXPECT_EQ(mem[3], 0x40);
    EXPECT_EQ(mem[4], 0x50);

    // 2) Enabling missing_dep or cycle manifest must fail.
    std::string msg;
    EXPECT_TRUE(!pm.EnableByName("missing_dep", msg));
    EXPECT_TRUE(!pm.EnableByName("cyc_a", msg));
    EXPECT_EQ(mem[2], 0x30);

    // 3) Disabling base must cascade-disable dependent too!
    EXPECT_TRUE(pm.DisableByName("base", msg));
    EXPECT_EQ(mem[1], 0x20);
    EXPECT_EQ(mem[0], 0x10);

    // 4) Re-enabling dependent while base is disabled must fail.
    EXPECT_TRUE(!pm.EnableByName("dependent", msg));
    EXPECT_EQ(mem[0], 0x10);

    // 5) Re-enabling base, then dependent must succeed.
    EXPECT_TRUE(pm.EnableByName("base", msg));
    EXPECT_TRUE(pm.EnableByName("dependent", msg));
    EXPECT_EQ(mem[1], 0x22);
    EXPECT_EQ(mem[0], 0x11);

    // 6) Reload with base disabled via config.rvt -> dependent stays disabled too!
    pm.ReloadAll(tmp_dir.string(), {"base"});
    EXPECT_EQ(mem[1], 0x20);
    EXPECT_EQ(mem[0], 0x10);

    pm.UnloadAll();
    VirtualFree(mem, 0, MEM_RELEASE);
    fs::remove_all(tmp_dir, ec);
}

} // namespace

int main() {
    std::cout << "=== Glitch Offline Test Suite ===\n";
    RunTest("RivetParser (syntax + errors + repo manifests)", TestRivetParser);
    RunTest("Scanner (byte pattern + hex + ASLR math)", TestScanner);
    RunTest("X64Disasm & Prologue Relocator (RIP-rel)", TestX64DisasmAndReloc);
    RunTest("StubAllocator (+-2GB alignment & owner free)", TestStubAllocator);
    RunTest("MemoryPatcher (verify, conflict guard, rollback)", TestMemoryPatcher);
    RunTest("HookEngine (live x64 detour + RIP-rel trampoline)", TestLiveFunctionHook);
    RunTest("PatchManager (.rvt declarative stub + live toggle)", TestRvtPatchManager);
    RunTest("LoaderRuntime + hello_ext.dll (IShareSys + cmd + unload)", TestExtensionEndToEnd);
    RunTest("PatchManager (required_manifests topo/gate/cascade/cycle)", TestRequiredManifests);

    std::cout << "\nSummary: " << g_pass << " passed, " << g_fail << " failed.\n";
    return g_fail == 0 ? 0 : 1;
}
