cmake_minimum_required(VERSION 3.16)
project(Glitch LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    # Static CRT (/MT) so winmm.dll, Glitch.dll, and GlitchConfig.exe carry zero extra runtime deps.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W4 /MP /EHsc /utf-8 /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX)
endif()

# ---- Core static library (shared between Glitch.dll, GlitchConfig.exe, and offline unit tests) ----
add_library(glitch_core STATIC
    src/core/logger.cpp
    src/core/rivet_parser.cpp
    src/core/config.cpp
    src/core/stub_alloc.cpp
    src/core/x64_disasm.cpp
    src/core/memory_patch.cpp
    src/core/hook_engine.cpp
    src/core/scanner.cpp
    src/core/patch_manager.cpp
    src/core/extension_manager.cpp
    src/core/console.cpp
    src/core/loader_main.cpp
)
target_include_directories(glitch_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/sdk
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

# ---- Glitch.dll (the core runtime loaded by winmm.dll) ----
add_library(Glitch SHARED
    src/core/dll_entry.cpp
)
target_link_libraries(Glitch PRIVATE glitch_core)

# ---- winmm.dll (thin proxy DLL exporting all 181 System32 winmm symbols) ----
add_library(winmm SHARED
    src/proxy/winmm_proxy.cpp
    src/proxy/winmm_thunks.asm
    src/proxy/entry_trampoline.asm
    src/proxy/winmm_exports.def
)
target_include_directories(winmm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy)
set_target_properties(winmm PROPERTIES OUTPUT_NAME "winmm")

# ---- Example native extension (hello_ext.dll) ----
add_library(hello_ext SHARED
    examples/hello_ext/hello_ext.cpp
)
target_include_directories(hello_ext PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sdk)

# ---- Lightweight native Win32 patch configurator GUI (GlitchConfig.exe) ----
add_executable(GlitchConfig WIN32
    src/config_gui/main.cpp
)
target_compile_definitions(GlitchConfig PRIVATE UNICODE _UNICODE)
target_link_libraries(GlitchConfig PRIVATE glitch_core comctl32 shell32 dwmapi uxtheme ole32 version)

# ---- Offline automated test suite (runs without the game!) ----
add_executable(glitch_tests
    tests/test_main.cpp
)
target_link_libraries(glitch_tests PRIVATE glitch_core)
add_dependencies(glitch_tests hello_ext)
target_compile_definitions(glitch_tests PRIVATE
    RIFT_TEST_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/.."
    RIFT_TEST_HELLO_EXT_DLL="$<TARGET_FILE:hello_ext>"
)
