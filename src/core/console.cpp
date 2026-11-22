#include "console.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <sstream>

namespace riftloader {

Console::Console(Logger& logger) : logger_(logger) {}

Console::~Console() {
    Stop();
}

bool Console::StartWindow(const std::string& title) {
    if (running_.load()) return true;

    if (!GetConsoleWindow()) {
        if (!AllocConsole()) return false;
        owns_console_ = true;
    }
    SetConsoleTitleA(title.c_str());

    // Disable QuickEdit mode so clicking the console window doesn't freeze the game!
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn && hIn != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hIn, &mode)) {
            mode &= ~ENABLE_QUICK_EDIT_MODE;
            mode |= ENABLE_EXTENDED_FLAGS;
            SetConsoleMode(hIn, mode);
        }
    }

    logger_.SetConsoleEnabled(true);
    running_.store(true);
    thread_ = std::thread(&Console::InputThreadProc, this);
    return true;
}

void Console::Stop() {
    if (!running_.exchange(false)) return;
    logger_.SetConsoleEnabled(false);

    // Wake up ReadConsoleA if blocked on stdin.
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn && hIn != INVALID_HANDLE_VALUE) {
        CancelIoEx(hIn, nullptr);
    }
    if (thread_.joinable()) {
        thread_.detach(); // Safe during DLL_PROCESS_DETACH shutdown
    }
    if (owns_console_) {
        FreeConsole();
        owns_console_ = false;
    }
}

RiftResult Console::RegisterCommand(RiftExtHandle owner, const std::string& name,
                                    const std::string& help, RiftCommandFn cb, void* user_data) {
    if (name.empty() || !cb) return RIFT_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(cmd_mutex_);
    if (commands_.count(name)) return RIFT_ERR_ALREADY_EXISTS;
    commands_[name] = {owner, name, help, cb, user_data};
    return RIFT_OK;
}

void Console::UnregisterCommand(const std::string& name) {
    std::lock_guard<std::mutex> lock(cmd_mutex_);
    commands_.erase(name);
}

void Console::UnregisterByOwner(RiftExtHandle owner) {
    if (owner == RIFT_INVALID_HANDLE) return;
    std::lock_guard<std::mutex> lock(cmd_mutex_);
    for (auto it = commands_.begin(); it != commands_.end(); ) {
        if (it->second.owner == owner) it = commands_.erase(it);
        else ++it;
    }
}

std::vector<std::string> Console::SplitArgs(const std::string& line) {
    std::vector<std::string> args;
    std::string cur;
    bool in_quote = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') {
            in_quote = !in_quote;
        } else if ((c == ' ' || c == '\t' || c == '\r' || c == '\n') && !in_quote) {
            if (!cur.empty()) {
                args.push_back(std::move(cur));
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) args.push_back(std::move(cur));
    return args;
}

bool Console::ExecuteLine(const std::string& line) {
    auto args = SplitArgs(line);
    if (args.empty()) return true;

    if (args[0] == "help" || args[0] == "?") {
        PrintHelp();
        return true;
    }

    CommandEntry entry;
    {
        std::lock_guard<std::mutex> lock(cmd_mutex_);
        auto it = commands_.find(args[0]);
        if (it == commands_.end()) {
            Print("Unknown command: '" + args[0] + "'. Type 'help' for available commands.\n");
            return false;
        }
        entry = it->second;
    }

    std::vector<const char*> argv;
    argv.reserve(args.size());
    for (const auto& a : args) argv.push_back(a.c_str());

    entry.cb(static_cast<int>(argv.size()), argv.data(), entry.user_data);
    return true;
}

void Console::Print(const std::string& text) {
    logger_.WriteRawConsole(text.c_str());
}

void Console::PrintHelp() {
    std::vector<CommandEntry> list;
    {
        std::lock_guard<std::mutex> lock(cmd_mutex_);
        for (const auto& kv : commands_) list.push_back(kv.second);
    }
    std::sort(list.begin(), list.end(),
              [](const CommandEntry& a, const CommandEntry& b) { return a.name < b.name; });

    std::ostringstream ss;
    ss << "Glitch Console Commands:\n";
    ss << "  help                 - Show this command list\n";
    for (const auto& c : list) {
        ss << "  " << c.name;
        if (c.name.size() < 20) ss << std::string(20 - c.name.size(), ' ');
        ss << " - " << c.help << "\n";
    }
    Print(ss.str());
}

void Console::InputThreadProc() {
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    char buf[1024];

    Print("Glitch interactive console ready. Type 'help' for commands.\n");
    while (running_.load()) {
        Print("rift> ");
        DWORD read = 0;
        if (!ReadConsoleA(hIn, buf, sizeof(buf) - 1, &read, nullptr)) {
            if (!running_.load()) break;
            Sleep(50);
            continue;
        }
        buf[read] = '\0';
        std::string line(buf, read);
        ExecuteLine(line);
    }
}

} // namespace riftloader
