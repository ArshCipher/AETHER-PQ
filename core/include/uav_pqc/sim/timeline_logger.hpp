// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file timeline_logger.hpp
 * @brief Timeline event recorder and visualizer for the UAV-PQC simulator.
 *
 * Records every protocol event (handshake start/complete, retransmit, TreeKEM
 * rekey, session expiry, heartbeat) during a simulation run and renders them
 * as either a structured JSON document or a human-readable ASCII swimlane
 * diagram for post-run analysis.
 *
 * ASCII swimlane example (truncated):
 * @code
 *  Time(ms)  │ GCS          │ UAV-0001     │ UAV-0002
 * ───────────┼──────────────┼──────────────┼──────────────
 *     0      │ [INIT]       │ [INIT]       │
 *    50      │              │ ─Handshake→  │
 *   115      │ ←ServerHello─│              │
 *   215      │              │ ─ClientAuth→ │
 *  ...
 * @endcode
 *
 * JSON structure:
 * @code
 * {
 *   "sim_duration_ms": 25000,
 *   "total_entries": 47,
 *   "timeline": [
 *     { "time_ms": 50, "node": "0001...", "kind": "Handshake",
 *       "label": "ClientHello sent", "meta": {} },
 *     ...
 *   ]
 * }
 * @endcode
 */

#include "uav_pqc/common/types.hpp"
#include "uav_pqc/sim/timer_manager.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// EventKind — semantic classification of timeline entries
// ─────────────────────────────────────────────────────────────────────────────

enum class TimelineEventKind : std::uint8_t {
    Init         = 0,
    Handshake    = 1,
    Retransmit   = 2,
    TreeKem      = 3,
    Session      = 4,
    Heartbeat    = 5,
    ChannelEvent = 6,   ///< Packet drop, duplicate, reorder
    Custom       = 7,
};

[[nodiscard]] std::string_view timeline_event_kind_name(TimelineEventKind k) noexcept;

/// Map a TimerKind to the corresponding TimelineEventKind.
[[nodiscard]] TimelineEventKind kind_from_timer(TimerKind k) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
// TimelineEntry
// ─────────────────────────────────────────────────────────────────────────────

struct TimelineEntry {
    Timestamp         time_ms;
    std::string       node_id_hex;      ///< Hex-encoded NodeId (or "GCS", "CA")
    TimelineEventKind kind;
    std::string       label;            ///< Short human-readable description
    nlohmann::json    metadata;         ///< Optional structured payload

    [[nodiscard]] nlohmann::json to_json() const;
};

// ─────────────────────────────────────────────────────────────────────────────
// TimelineLogger
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Collects timeline entries during a simulation and renders them.
 *
 * Thread safety: NOT thread-safe.
 */
class TimelineLogger {
public:
    TimelineLogger() = default;
    ~TimelineLogger() = default;

    TimelineLogger(const TimelineLogger&)            = delete;
    TimelineLogger& operator=(const TimelineLogger&) = delete;
    TimelineLogger(TimelineLogger&&)                 = default;
    TimelineLogger& operator=(TimelineLogger&&)      = default;

    // ── Recording ─────────────────────────────────────────────────────────────

    /**
     * @brief Record a timeline event.
     * @param time_ms     Virtual simulation time when the event occurred.
     * @param node_id_hex Hex node identifier (or symbolic name like "GCS").
     * @param kind        Semantic category.
     * @param label       Human-readable description.
     * @param metadata    Optional JSON metadata (defaults to null object).
     */
    void record(Timestamp            time_ms,
                std::string          node_id_hex,
                TimelineEventKind    kind,
                std::string          label,
                nlohmann::json       metadata = nullptr);

    /// Convenience overload that maps a TimerKind to TimelineEventKind.
    void record_timer(Timestamp         time_ms,
                      std::string       node_id_hex,
                      TimerKind         kind,
                      std::string       label,
                      nlohmann::json    metadata = nullptr);

    // ── Accessors ─────────────────────────────────────────────────────────────

    [[nodiscard]] const std::vector<TimelineEntry>& entries() const noexcept {
        return entries_;
    }

    [[nodiscard]] std::size_t entry_count() const noexcept { return entries_.size(); }

    /// True if no entries have been recorded.
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

    /// Returns the maximum virtual time recorded, or 0 if empty.
    [[nodiscard]] Timestamp duration_ms() const noexcept { return max_time_ms_; }

    // ── Serialization ─────────────────────────────────────────────────────────

    /**
     * @brief Serialize all entries to a JSON document.
     *
     * @param sim_duration_ms  Total simulation duration for the header field.
     */
    [[nodiscard]] nlohmann::json to_json(Timestamp sim_duration_ms = 0) const;

    /**
     * @brief Render an ASCII swimlane diagram.
     *
     * Produces a grid with one column per node and one row per 
     * `bin_width_ms` virtual milliseconds.  Events are placed in the cell
     * corresponding to their time and node.
     *
     * @param bin_width_ms  Time resolution of each row (default: 100 ms).
     * @param lane_width    Character width per node lane (default: 22).
     * @return              ASCII string suitable for direct stdout output.
     */
    [[nodiscard]] std::string to_ascii(Timestamp bin_width_ms = 100,
                                       std::size_t lane_width = 22) const;

    // ── File export ───────────────────────────────────────────────────────────

    /// Write JSON to a file.  Returns false on I/O error.
    bool write_json(const std::string& path, Timestamp sim_duration_ms = 0) const;

    /// Write ASCII diagram to a file.  Returns false on I/O error.
    bool write_ascii(const std::string& path,
                     Timestamp bin_width_ms = 100,
                     std::size_t lane_width = 22) const;

    // ── Reset ─────────────────────────────────────────────────────────────────

    /// Clear all entries (for deterministic replay support).
    void reset() noexcept;

private:
    std::vector<TimelineEntry> entries_;
    Timestamp                  max_time_ms_ = 0;
};

} // namespace uav_pqc::sim
