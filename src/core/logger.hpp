#pragma once

#include "rift_sdk.h"

#include <cstdarg>
#include <mutex>
#include <string>

namespace riftloader {

class Logger {
public:
    Logger() = default;
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    bool OpenFile(const std::string& path);
    void CloseFile();

    void SetMinLevel(RiftLogLevel level);
    RiftLogLevel GetMinLevel() const;
    void SetConsoleEnabled(bool enabled);

    void Log(RiftLogLevel level, const char* tag, const char* fmt, ...);
    void LogV(RiftLogLevel level, const char* tag, const char* fmt, va_list args);
    void WriteRawConsole(const char* text);

    static RiftLogLevel ParseLevel(const std::string& str, RiftLogLevel fallback = RIFT_LOG_INFO);
    static const char* LevelName(RiftLogLevel level);

private:
    mutable std::mutex mutex_;
    FILE* file_ = nullptr;
    RiftLogLevel min_level_ = RIFT_LOG_INFO;
    bool console_enabled_ = false;
};

} // namespace riftloader
