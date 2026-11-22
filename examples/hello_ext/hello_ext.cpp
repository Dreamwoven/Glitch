/*
 * hello_ext - Minimal SourceMod-style native extension example for RiftLoader.
 *
 * Demonstrates:
 *   1. RiftExt_Query / RiftExt_Load / RiftExt_Unload exports
 *   2. Registering a live console command ("hello")
 *   3. Exposing a shared interface via IShareSys ("IHelloService" v1)
 *   4. Subscribing to lifecycle events ("loader.all_loaded")
 */

#include "rift_sdk.hpp"

#include <cstdio>

namespace {

rift::Context g_ctx;
int g_ping_count = 0;

struct IHelloService {
    int (*GetPingCount)(void);
    int (*AddNumbers)(int a, int b);
};

int Hello_GetPingCount(void) { return g_ping_count; }
int Hello_AddNumbers(int a, int b) { return a + b; }

IHelloService g_hello_iface = {
    Hello_GetPingCount,
    Hello_AddNumbers,
};

void CmdHello(int argc, const char* const* argv, void*) {
    ++g_ping_count;
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "hello_ext says hi! (ping #%d, argc=%d, game_base=0x%llX)\n",
                  g_ping_count, argc,
                  static_cast<unsigned long long>(g_ctx.GameBase()));
    g_ctx.Raw()->ConsolePrint(buf);
    if (argc > 1) {
        g_ctx.Raw()->Log(RIFT_LOG_INFO, "hello_ext", "arg[1] = %s", argv[1]);
    }
}

void OnAllLoaded(const char*, const void*, void*) {
    g_ctx.Raw()->Log(RIFT_LOG_INFO, "hello_ext",
                     "Received loader.all_loaded - ready for action!");
}

} // namespace

extern "C" {

RIFT_EXT_EXPORT bool RiftExt_Query(RiftExtensionInfo* out_info) {
    if (!out_info || out_info->struct_size < sizeof(RiftExtensionInfo)) return false;
    out_info->api_version = RIFT_SDK_API_VERSION;
    out_info->name = "hello_ext";
    out_info->version = "0.1.0";
    out_info->author = "RiftLoader";
    out_info->description = "Minimal template extension (command + shared interface + event)";
    return true;
}

RIFT_EXT_EXPORT bool RiftExt_Load(const RiftLoaderAPI* api, RiftExtHandle self) {
    if (!api || api->api_version != RIFT_SDK_API_VERSION) return false;
    g_ctx = rift::Context(api, self);
    g_ping_count = 0;

    g_ctx.RegisterCommand("hello", "Example command registered by hello_ext", CmdHello);
    g_ctx.RegisterInterface("IHelloService", 1, &g_hello_iface);
    g_ctx.Subscribe("loader.all_loaded", OnAllLoaded);

    api->Log(RIFT_LOG_INFO, "hello_ext", "Loaded! Try typing 'hello' in the RiftLoader console.");
    return true;
}

RIFT_EXT_EXPORT void RiftExt_Unload(void) {
    // RiftLoader automatically cleans up our commands, interfaces, hooks, patches,
    // events, and executable stubs right after RiftExt_Unload returns.
    if (g_ctx.Valid()) {
        g_ctx.Raw()->Log(RIFT_LOG_INFO, "hello_ext", "Unloading (served %d pings).", g_ping_count);
    }
    g_ctx = {};
}

} // extern "C"
