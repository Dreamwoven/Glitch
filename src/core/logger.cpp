#include "logger.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <vector>

namespace riftloader {

Logger::~Logger() {
    CloseFile();
}

bool Logger::OpenFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_) {
        std::fclose(file_);
        file_ = nullptr;
    }
    try {
        std::filesystem::path p(path);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
    } catch (...) {
    }
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) {
        return false;
    }
    file_ = f;
    return true;
}

void Logger::CloseFile() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_) {
        std::fflush(file_);
        std::fclose(file_);
        file_ = nullptr;
    }
}

void Logger::SetMinLevel(RiftLogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_level_ = level;
}

RiftLogLevel Logger::GetMinLevel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return min_level_;
}

void Logger::SetConsoleEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    console_enabled_ = enabled;
}

void Logger::Log(RiftLogLevel level, const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogV(level, tag, fmt, args);
    va_end(args);
}

void Logger::LogV(RiftLogLevel level, const char* tag, const char* fmt, va_list args) {
    if (!fmt) return;

    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    if (needed < 0) return;

    std::vector<char> buf(static_cast<size_t>(needed) + 1);
    std::vsnprintf(buf.data(), buf.size(), fmt, args);

    SYSTEMTIME st{};
    GetLocalTime(&st);

    char header[96];
    std::snprintf(header, sizeof(header), "[%02u:%02u:%02u.%03u] [%-5s] [%s] ",
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                  LevelName(level), tag ? tag : "loader");

    std::lock_guard<std::mutex> lock(mutex_);
    if (level < min_level_) return;

    if (file_) {
        std::fwrite(header, 1, std::strlen(header), file_);
        std::fwrite(buf.data(), 1, static_cast<size_t>(needed), file_);
        std::fputc('\n', file_);
        std::fflush(file_);
    }

    if (console_enabled_) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut && hOut != INVALID_HANDLE_VALUE) {
            CONSOLE_SCREEN_BUFFER_INFO csbi{};
            bool has_attr = GetConsoleScreenBufferInfo(hOut, &csbi) != 0;
            WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            switch (level) {
                case RIFT_LOG_TRACE: color = FOREGROUND_INTENSITY; break;
                case RIFT_LOG_DEBUG: color = FOREGROUND_GREEN | FOREGROUND_BLUE; break;
                case RIFT_LOG_INFO:  color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
                case RIFT_LOG_WARN:  color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
                case RIFT_LOG_ERROR: color = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
            }
            if (has_attr) SetConsoleTextAttribute(hOut, color);
            DWORD written = 0;
            WriteConsoleA(hOut, header, static_cast<DWORD>(std::strlen(header)), &written, nullptr);
            WriteConsoleA(hOut, buf.data(), static_cast<DWORD>(needed), &written, nullptr);
            WriteConsoleA(hOut, "\r\n", 2, &written, nullptr);
            if (has_attr) SetConsoleTextAttribute(hOut, csbi.wAttributes);
        }
    }
}

void Logger::WriteRawConsole(const char* text) {
    if (!text) return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_) {
        std::fputs(text, file_);
        std::fflush(file_);
    }
    if (console_enabled_) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut && hOut != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteConsoleA(hOut, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        }
    }
}

RiftLogLevel Logger::ParseLevel(const std::string& str, RiftLogLevel fallback) {
    std::string low = str;
    std::transform(low.begin(), low.end(), low.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (low == "trace") return RIFT_LOG_TRACE;
    if (low == "debug") return RIFT_LOG_DEBUG;
    if (low == "info")  return RIFT_LOG_INFO;
    if (low == "warn" || low == "warning") return RIFT_LOG_WARN;
    if (low == "error" || low == "err") return RIFT_LOG_ERROR;
    return fallback;
}

const char* Logger::LevelName(RiftLogLevel level) {
    switch (level) {
        case RIFT_LOG_TRACE: return "TRACE";
        case RIFT_LOG_DEBUG: return "DEBUG";
        case RIFT_LOG_INFO:  return "INFO";
        case RIFT_LOG_WARN:  return "WARN";
        case RIFT_LOG_ERROR: return "ERROR";
        default:             return "INFO";
    }
}

} // namespace riftloader
