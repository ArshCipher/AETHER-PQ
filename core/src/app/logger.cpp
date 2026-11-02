// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/logger.hpp"
#include "uav_pqc/common/logging.hpp"

namespace uav_pqc::app {

namespace {

spdlog::level::level_enum to_spdlog_level(LogLevel lvl) noexcept {
    switch (lvl) {
        case LogLevel::Trace:    return spdlog::level::trace;
        case LogLevel::Debug:    return spdlog::level::debug;
        case LogLevel::Info:     return spdlog::level::info;
        case LogLevel::Warn:     return spdlog::level::warn;
        case LogLevel::Error:    return spdlog::level::err;
        case LogLevel::Critical: return spdlog::level::critical;
    }
    return spdlog::level::info;
}

} // namespace

Logger::Logger(LogLevel level) : level_(level) {
    logging::init(to_spdlog_level(level_));
}

void Logger::log(LogLevel level, std::string_view context, std::string_view message) {
    auto log_impl = logging::get_logger(context);
    if (!log_impl) return;

    switch (level) {
        case LogLevel::Trace:
            SPDLOG_LOGGER_TRACE(log_impl, "{}", message);
            break;
        case LogLevel::Debug:
            SPDLOG_LOGGER_DEBUG(log_impl, "{}", message);
            break;
        case LogLevel::Info:
            SPDLOG_LOGGER_INFO(log_impl, "{}", message);
            break;
        case LogLevel::Warn:
            SPDLOG_LOGGER_WARN(log_impl, "{}", message);
            break;
        case LogLevel::Error:
            SPDLOG_LOGGER_ERROR(log_impl, "{}", message);
            break;
        case LogLevel::Critical:
            SPDLOG_LOGGER_CRITICAL(log_impl, "{}", message);
            break;
    }
}

void Logger::set_level(LogLevel level) {
    level_ = level;
    logging::set_global_level(to_spdlog_level(level));
}

void Logger::flush() {
    logging::flush_all();
}

} // namespace uav_pqc::app
