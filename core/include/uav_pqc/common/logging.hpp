// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file logging.hpp
 * @brief Thin logging façade over spdlog.
 *
 * All internal library code calls the macros defined here.  The façade
 * guarantees that:
 *  1. Replacing spdlog with a different backend is a single-file change.
 *  2. On embedded targets (UAV_PQC_EMBEDDED=ON) the macros can be defined
 *     to no-ops, eliminating the dependency on spdlog entirely.
 *  3. Callers never interact with spdlog API directly.
 *
 * Usage:
 *   UAV_PQC_LOG_TRACE("ctx", "Key size = {}", key.size());
 *   UAV_PQC_LOG_DEBUG("ctx", "Handshake mode: {}", mode_name(mode));
 *   UAV_PQC_LOG_INFO ("ctx", "Session {} established", to_hex(id));
 *   UAV_PQC_LOG_WARN ("ctx", "Session nearing nonce exhaustion");
 *   UAV_PQC_LOG_ERROR("ctx", "ML-KEM decapsulation failed: {}", err.message);
 *   UAV_PQC_LOG_CRITICAL("ctx", "Trust chain broken — aborting");
 */

#ifndef UAV_PQC_EMBEDDED

#include <spdlog/spdlog.h>
#include <memory>
#include <string_view>

namespace uav_pqc::logging {

/// Retrieve or create the named spdlog logger for the given subsystem.
std::shared_ptr<spdlog::logger> get_logger(std::string_view name);

/// Global library log level — can be overridden at runtime before any call.
void set_global_level(spdlog::level::level_enum level);

/// Flush all sinks (call on shutdown or critical error paths).
void flush_all();

/// Initialise the library logger with optional sink; idempotent.
void init(spdlog::level::level_enum level = spdlog::level::info);

} // namespace uav_pqc::logging

// ── Logging macros ─────────────────────────────────────────────────────────────
// Each macro creates the logger lazily (cached after the first call).

#define UAV_PQC_LOG_TRACE(ctx, ...)    \
    SPDLOG_LOGGER_TRACE(::uav_pqc::logging::get_logger(ctx), __VA_ARGS__)

#define UAV_PQC_LOG_DEBUG(ctx, ...)    \
    SPDLOG_LOGGER_DEBUG(::uav_pqc::logging::get_logger(ctx), __VA_ARGS__)

#define UAV_PQC_LOG_INFO(ctx, ...)     \
    SPDLOG_LOGGER_INFO(::uav_pqc::logging::get_logger(ctx), __VA_ARGS__)

#define UAV_PQC_LOG_WARN(ctx, ...)     \
    SPDLOG_LOGGER_WARN(::uav_pqc::logging::get_logger(ctx), __VA_ARGS__)

#define UAV_PQC_LOG_ERROR(ctx, ...)    \
    SPDLOG_LOGGER_ERROR(::uav_pqc::logging::get_logger(ctx), __VA_ARGS__)

#define UAV_PQC_LOG_CRITICAL(ctx, ...) \
    SPDLOG_LOGGER_CRITICAL(::uav_pqc::logging::get_logger(ctx), __VA_ARGS__)

#else // UAV_PQC_EMBEDDED — all logging is compiled out

namespace uav_pqc::logging {
inline void set_global_level(int /*level*/) noexcept {}
inline void flush_all() noexcept {}
inline void init(int /*level*/ = 0) noexcept {}
} // namespace uav_pqc::logging

#define UAV_PQC_LOG_TRACE(ctx, ...)    do {} while(false)
#define UAV_PQC_LOG_DEBUG(ctx, ...)    do {} while(false)
#define UAV_PQC_LOG_INFO(ctx, ...)     do {} while(false)
#define UAV_PQC_LOG_WARN(ctx, ...)     do {} while(false)
#define UAV_PQC_LOG_ERROR(ctx, ...)    do {} while(false)
#define UAV_PQC_LOG_CRITICAL(ctx, ...) do {} while(false)

#endif // UAV_PQC_EMBEDDED
