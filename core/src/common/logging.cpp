// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file logging.cpp
 * @brief Logging façade implementation — spdlog initialisation and logger registry.
 */

#ifndef UAV_PQC_EMBEDDED

#include "uav_pqc/common/logging.hpp"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/async.h>

#include <mutex>
#include <unordered_map>

namespace uav_pqc::logging {

namespace {

std::mutex                                          g_registry_mutex;
std::unordered_map<std::string, std::shared_ptr<spdlog::logger>> g_registry;
spdlog::level::level_enum                           g_global_level = spdlog::level::info;
bool                                                g_initialized  = false;

/// Create a console logger for the given subsystem name.
std::shared_ptr<spdlog::logger> create_logger(const std::string& name) {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(g_global_level);
    console_sink->set_pattern("[%Y-%m-%dT%H:%M:%S.%e] [%n] [%^%l%$] %v");

    auto logger = std::make_shared<spdlog::logger>(name, console_sink);
    logger->set_level(g_global_level);
    logger->flush_on(spdlog::level::warn);
    spdlog::register_logger(logger);
    return logger;
}

} // anonymous namespace

void init(spdlog::level::level_enum level) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    if (g_initialized) {
        return;
    }
    g_global_level = level;
    spdlog::set_level(level);
    spdlog::set_pattern("[%Y-%m-%dT%H:%M:%S.%e] [%n] [%^%l%$] %v");
    g_initialized = true;
}

std::shared_ptr<spdlog::logger> get_logger(std::string_view name) {
    const std::string key{name};

    // Fast path: look up in our local cache under the mutex
    {
        std::lock_guard<std::mutex> lock(g_registry_mutex);
        auto it = g_registry.find(key);
        if (it != g_registry.end()) {
            return it->second;
        }
    }

    // Slow path: create and register
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    // Re-check after acquiring the lock (double-checked locking pattern)
    auto it = g_registry.find(key);
    if (it != g_registry.end()) {
        return it->second;
    }

    auto logger       = create_logger(key);
    g_registry[key]   = logger;
    return logger;
}

void set_global_level(spdlog::level::level_enum level) {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    g_global_level = level;
    spdlog::set_level(level);
    for (auto& [name, logger] : g_registry) {
        logger->set_level(level);
    }
}

void flush_all() {
    std::lock_guard<std::mutex> lock(g_registry_mutex);
    for (auto& [name, logger] : g_registry) {
        logger->flush();
    }
}

} // namespace uav_pqc::logging

#endif // UAV_PQC_EMBEDDED
