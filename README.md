# Glitch - Runtime Performance Patch & Extension Loader for *Ratchet & Clank: Rift Apart* (PC)

Lightweight runtime patch and native C++ extension loader for **Ratchet & Clank: Rift Apart (Steam PC v3.630.1.0)**.
Drops cleanly beside your pristine, unmodified `RiftApart.exe` - no modified game executables, no launch options required.

## Install (Players)

1. Extract the release zip anywhere (e.g. your Downloads folder) and double-click **`GlitchConfig.exe`**.
2. Glitch automatically detects your Steam install of *Ratchet & Clank: Rift Apart* (or click **Browse...** for a custom folder). Click **Install** (or **Save & Launch Game**).

You can also extract the zip directly into your game folder (usually `C:\Program Files (x86)\Steam\steamapps\common\Ratchet & Clank - Rift Apart`) and launch from Steam as usual.

**Uninstall:** Click **Uninstall** in `GlitchConfig.exe`, or delete `winmm.dll` from your game folder. Your `RiftApart.exe` is never modified on disk.

> **Version safety:** Every patch verifies original bytes in memory before applying. If a future game update changes a target function, that patch is safely skipped and logged to `glitch/glitch.log`.

### Folder Layout
```
<Rift Apart Install>/
├── RiftApart.exe        # Pristine, untouched Steam binary
├── winmm.dll            # Thin proxy bootstrapper
├── Glitch.dll           # Core runtime
├── GlitchConfig.exe     # Dark-mode GUI patch manager
└── glitch/
    ├── config.rvt       # Loader settings (managed by GlitchConfig.exe)
    ├── glitch.log       # Runtime log
    ├── patches/         # Declarative .rvt performance patches
    └── extensions/      # Native x64 .dll extensions (optional)
```

## Included Performance Patches

All 15 included patches are enabled by default and designed to preserve visual fidelity:

| Patch | What It Does |
|---|---|
| **Faster Texture Hashing** | Speeds up CPU texture table lookups with identical visual output. |
| **Faster Random Number Generation** | Optimizes internal random number generation on the CPU with identical results. |
| **Skip Distant Terrain Self-Shadows** | Reduces GPU shadow workload by skipping redundant terrain hill self-shadowing. |
| **Volumetric Fog Depth 75%** | Lowers volumetric fog depth precision by 25% for a noticeable GPU speedup with minimal visual difference. |
| **CPU Asset Decompression** | Moves asset decompression from the GPU to the CPU, freeing GPU headroom during streaming and traversal. |
| **Smoother Lighting Probe Updates** | Spreads out environment lighting updates to reduce periodic frame-time spikes. |
| **Skip Local Hair & Fur Shadows** | Stops hair and fur strands from casting extra shadows from small local lights to save GPU time. |
| **Skip Skin Fuzz Post-Pass** | Skips a subtle full-resolution skin fuzz blending pass for extra GPU performance. |
| **Half-Res Cloud Shadows** | Halves volumetric cloud shadow map resolution to reduce GPU load with virtually no visible change. |
| **Skip Smoke & Fog Shadow Casting** | Stops volumetric smoke and fog effects from casting extra shadows onto the scene. |
| **Half-Res Light Shafts** | Halves internal light-shaft (god ray) buffer resolution for faster rendering with soft, similar visuals. |
| **Free Unused Ray-Tracing VRAM** | Prevents the game from allocating unused ray-tracing buffers when ray tracing is turned off (saves ~26-58 MB VRAM). |
| **Async Background Asset Loading** | Enables background DirectX 12 resource creation to reduce traversal and streaming stutter *(requires Async Asset Loading Crash Fix)*. |
| **Async Asset Loading Crash Fix** | Required stability fix that prevents crashes when Async Background Asset Loading is enabled. |
| **Trim Rough-Surface Reflections** | Slightly tightens screen-space reflection cutoff on rough surfaces for faster GPU performance (when RT is off). |

---

## Architecture (Developers)

- **`winmm.dll` (thin proxy)** - Exports all 181 `System32\winmm.dll` symbols (names + ordinals, including `NONAME @2`) via x64 MASM jump thunks. Places a one-shot 14-byte trampoline on `RiftApart.exe`'s PE EntryPoint (`WinMainCRTStartup`) so `Glitch.dll` initializes deterministically on the main thread with the OS loader lock free, before CRT `_initterm` and `WinMain`.
- **`Glitch.dll` (core runtime)** - C++17 runtime with:
  - Declarative `.rvt` manifests (`glitch/patches/*.rvt`) supporting ASLR-safe static VAs, RVAs, byte patterns, original-byte verification, conflict detection, near ±2 GB patch stubs (`stub_bytes` + `stub_fixups`), and topological dependency enforcement (`required_manifests`).
  - SourceMod-style native `.dll` extension SDK (`sdk/rift_sdk.h` + `sdk/rift_sdk.hpp`) with x64 function detouring, executable stubs, byte-pattern scanning, `IShareSys`-style shared interfaces, named events, and live load/unload/reload.
  - Optional interactive Win32 console (`console.true` in `glitch/config.rvt`) and file logger.
- **`GlitchConfig.exe`** - Zero-dependency native Win32 dark-mode GUI configurator that reads `.rvt` manifests, enforces `required_manifests` live in the UI, and writes `glitch/config.rvt`.

## Building from Source

Requires Visual Studio (MSVC x64 + MASM) and CMake 3.16+:

```powershell
cmake -S . -B build -G "Visual Studio 16 2019" -A x64
cmake --build build --config Release
.\build\Release\glitch_tests.exe
```

## Declarative `.rvt` Patch Format

Drop any `.rvt` file into `glitch/patches/`. Supports static VAs (`0x14xxxxxxx`, auto-adjusted for ASLR), RVAs, byte patterns (`??` wildcards), patch stub detours (`stub_bytes` / `stub_fixups`), and manifest dependencies (`required_manifests`):

```rvt
name."my_patch"
display_name."My Patch"
description."Plain-English description shown in GlitchConfig."
enabled.true
required_manifests.arr;
	."some_prerequisite_patch"

patches.arr;
	.obj;
		id."example_site"
		va."0x1410C5B57"
		orig."0F 84 A7 00 00 00"
		bytes."E9 A8 00 00 00 90"
```

## Writing a Native C++ Extension

Include `sdk/rift_sdk.hpp` (or pure C `sdk/rift_sdk.h`) and export the 3 lifecycle functions:

```cpp
#include "rift_sdk.hpp"

static rift::Context g_ctx;
using TargetFn = void (*)(void* self);
static TargetFn g_orig = nullptr;

static void MyDetour(void* self) {
    g_orig(self);
}

extern "C" {
RIFT_EXT_EXPORT bool RiftExt_Query(RiftExtensionInfo* out) {
    out->api_version = RIFT_SDK_API_VERSION;
    out->name = "my_mod";
    out->version = "0.1.0";
    out->author = "you";
    out->description = "Example native extension";
    return true;
}

RIFT_EXT_EXPORT bool RiftExt_Load(const RiftLoaderAPI* api, RiftExtHandle self) {
    g_ctx = rift::Context(api, self);
    return g_ctx.HookVa("my_hook", 0x1410DEDD0, &MyDetour, &g_orig) == RIFT_OK;
}

RIFT_EXT_EXPORT void RiftExt_Unload(void) {
    // Hooks, patches, stubs, commands, events, and interfaces owned by `self`
    // are automatically cleaned up by Glitch after RiftExt_Unload().
}
}
```

See [examples/hello_ext/hello_ext.cpp](examples/hello_ext/hello_ext.cpp) for a complete template using commands, `IShareSys` shared interfaces, and lifecycle events.

## Live Console Commands

Enable `Show debug console window on game launch` in `GlitchConfig.exe` (or set `console.true` in `glitch/config.rvt`) to use the live console:

- `help` - list all built-in and extension-registered commands
- `status` - show live ASLR base, slide, patch/extension/hook/stub counts
- `patch list | enable <name> | disable <name> | toggle <name> | reload`
- `ext list | load <dll> | unload <name> | reload <name>`
- `mem read <va:0x14...|0x...> [len]` - hex-dump live game memory
- `mem scan <byte pattern>` - live signature scan
- `loglevel <trace|debug|info|warn|error>`

## License & Contributions

Licensed under the **PolyForm Noncommercial License 1.0.0** (see [LICENSE](LICENSE)). Free to use, fork, and modify for noncommercial purposes; commercial use is prohibited.

Pull requests are not accepted. Feel free to fork under the license.
