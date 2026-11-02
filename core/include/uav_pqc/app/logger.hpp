// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include <string_view>
#include <memory>

namespace uav_pqc::app {

/**
 * @brief Log level options mapping to internal logging levels.
 */
enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical
};

/**
 * @brief Abstract Logger interface.
 */
class ILogger {
public:
    ILogger() = default;
    virtual ~ILogger() = default;

    ILogger(const ILogger&) = delete;
    ILogger& operator=(const ILogger&) = delete;
    ILogger(ILogger&&) noexcept = default;
    ILogger& operator=(ILogger&&) noexcept = default;

    /**
     * @brief Log a formatted string.
     */
    virtual void log(LogLevel level, std::string_view context, std::string_view message) = 0;

    /**
     * @brief Set logging level.
     */
    virtual void set_level(LogLevel level) = 0;

    /**
     * @brief Flush logs immediately.
     */
    virtual void flush() = 0;
};

/**
 * @brief Thread-safe concrete Logger wrapping the internal logging backend.
 */
class Logger final : public ILogger {
public:
    explicit Logger(LogLevel level = LogLevel::Info);
    ~Logger() override = default;

    void log(LogLevel level, std::string_view context, std::string_view message) override;
    void set_level(LogLevel level) override;
    void flush() override;

private:
    LogLevel level_;
};

} // namespace uav_pqc::app
