#pragma once

#include "logger.hpp"
#include "rift_sdk.h"

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace riftloader {

class Console {
public:
    explicit Console(Logger& logger);
    ~Console();

    Console(const Console&) = delete;
    Console& operator=(const Console&) = delete;

    // Allocates a Win32 console window and starts the background command loop.
    bool StartWindow(const std::string& title);
    void Stop();

    RiftResult RegisterCommand(RiftExtHandle owner, const std::string& name,
                               const std::string& help, RiftCommandFn cb, void* user_data);
    void UnregisterCommand(const std::string& name);
    void UnregisterByOwner(RiftExtHandle owner);

    // Executes one command line (also directly callable from tests without a Win32 window).
    bool ExecuteLine(const std::string& line);
    void Print(const std::string& text);
    void PrintHelp();

private:
    struct CommandEntry {
        RiftExtHandle owner = RIFT_INVALID_HANDLE;
        std::string name;
        std::string help;
        RiftCommandFn cb = nullptr;
        void* user_data = nullptr;
    };

    void InputThreadProc();
    static std::vector<std::string> SplitArgs(const std::string& line);

    Logger& logger_;
    mutable std::mutex cmd_mutex_;
    std::unordered_map<std::string, CommandEntry> commands_;

    std::atomic<bool> running_{false};
    bool owns_console_{false};
    std::thread thread_;
};

} // namespace riftloader
