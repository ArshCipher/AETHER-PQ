// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/sim/timeline_logger.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

std::string_view timeline_event_kind_name(TimelineEventKind k) noexcept {
    switch (k) {
        case TimelineEventKind::Init:         return "Init";
        case TimelineEventKind::Handshake:    return "Handshake";
        case TimelineEventKind::Retransmit:   return "Retransmit";
        case TimelineEventKind::TreeKem:      return "TreeKem";
        case TimelineEventKind::Session:      return "Session";
        case TimelineEventKind::Heartbeat:    return "Heartbeat";
        case TimelineEventKind::ChannelEvent: return "ChannelEvent";
        case TimelineEventKind::Custom:       return "Custom";
    }
    return "Unknown";
}

TimelineEventKind kind_from_timer(TimerKind k) noexcept {
    switch (k) {
        case TimerKind::Retransmit: return TimelineEventKind::Retransmit;
        case TimerKind::Handshake:  return TimelineEventKind::Handshake;
        case TimerKind::TreeKem:    return TimelineEventKind::TreeKem;
        case TimerKind::Session:    return TimelineEventKind::Session;
        case TimerKind::Heartbeat:  return TimelineEventKind::Heartbeat;
        case TimerKind::Custom:     return TimelineEventKind::Custom;
    }
    return TimelineEventKind::Custom;
}

// ─────────────────────────────────────────────────────────────────────────────
// TimelineEntry
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json TimelineEntry::to_json() const {
    nlohmann::json j = {
        {"time_ms",  time_ms},
        {"node",     node_id_hex},
        {"kind",     std::string(timeline_event_kind_name(kind))},
        {"label",    label},
    };
    if (!metadata.is_null()) {
        j["meta"] = metadata;
    }
    return j;
}

// ─────────────────────────────────────────────────────────────────────────────
// TimelineLogger — recording
// ─────────────────────────────────────────────────────────────────────────────

void TimelineLogger::record(Timestamp         time_ms,
                             std::string       node_id_hex,
                             TimelineEventKind kind,
                             std::string       label,
                             nlohmann::json    metadata) {
    entries_.push_back(TimelineEntry{
        time_ms,
        std::move(node_id_hex),
        kind,
        std::move(label),
        std::move(metadata)
    });
    if (time_ms > max_time_ms_) max_time_ms_ = time_ms;
}

void TimelineLogger::record_timer(Timestamp      time_ms,
                                   std::string    node_id_hex,
                                   TimerKind      kind,
                                   std::string    label,
                                   nlohmann::json metadata) {
    record(time_ms, std::move(node_id_hex), kind_from_timer(kind),
           std::move(label), std::move(metadata));
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON serialization
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json TimelineLogger::to_json(Timestamp sim_duration_ms) const {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& e : entries_) {
        arr.push_back(e.to_json());
    }
    return {
        {"sim_duration_ms", sim_duration_ms > 0 ? sim_duration_ms : max_time_ms_},
        {"total_entries",   entries_.size()},
        {"timeline",        std::move(arr)},
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// ASCII swimlane diagram
// ─────────────────────────────────────────────────────────────────────────────

std::string TimelineLogger::to_ascii(Timestamp   bin_width_ms,
                                      std::size_t lane_width) const {
    if (entries_.empty()) return "(no timeline events recorded)\n";

    // ── 1. Collect ordered node list ──────────────────────────────────────
    // Use insertion order preserved by a vector + seen set
    std::vector<std::string> nodes;
    std::set<std::string>    seen;
    for (const auto& e : entries_) {
        if (seen.insert(e.node_id_hex).second) {
            nodes.push_back(e.node_id_hex);
        }
    }

    // ── 2. Build time-bin → node → events map ─────────────────────────────
    if (bin_width_ms == 0) bin_width_ms = 1;
    std::map<Timestamp, std::map<std::string, std::vector<std::string>>> grid;

    for (const auto& e : entries_) {
        Timestamp bin = (e.time_ms / bin_width_ms) * bin_width_ms;
        // Truncate label to fit lane_width - 2
        std::string lbl = e.label;
        const std::size_t max_lbl = lane_width > 4 ? lane_width - 4 : 1;
        if (lbl.size() > max_lbl) {
            lbl = lbl.substr(0, max_lbl - 1) + "~";
        }
        grid[bin][e.node_id_hex].push_back("[" + lbl + "]");
    }

    // ── 3. Render ─────────────────────────────────────────────────────────
    std::ostringstream oss;

    // Header
    const std::size_t time_col = 10;
    std::string sep(time_col, '-');

    oss << std::setw(static_cast<int>(time_col)) << "Time(ms)";
    for (const auto& n : nodes) {
        std::string header = n.size() > lane_width - 2
                             ? n.substr(0, lane_width - 2)
                             : n;
        oss << " | " << std::left << std::setw(static_cast<int>(lane_width))
            << header;
    }
    oss << '\n';

    // Separator
    oss << std::string(time_col, '-');
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        oss << "-+-" << std::string(lane_width, '-');
    }
    oss << '\n';

    // Rows
    for (const auto& [bin_time, node_map] : grid) {
        // Determine max number of sub-rows needed for this time bin
        std::size_t max_rows = 1;
        for (const auto& [node, evts] : node_map) {
            max_rows = std::max(max_rows, evts.size());
        }

        for (std::size_t row = 0; row < max_rows; ++row) {
            if (row == 0) {
                oss << std::right << std::setw(static_cast<int>(time_col)) << bin_time;
            } else {
                oss << std::string(time_col, ' ');
            }

            for (const auto& n : nodes) {
                oss << " | ";
                auto it = node_map.find(n);
                if (it != node_map.end() && row < it->second.size()) {
                    oss << std::left
                        << std::setw(static_cast<int>(lane_width))
                        << it->second[row];
                } else {
                    oss << std::string(lane_width, ' ');
                }
            }
            oss << '\n';
        }
    }

    return oss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
// File export
// ─────────────────────────────────────────────────────────────────────────────

bool TimelineLogger::write_json(const std::string& path,
                                 Timestamp sim_duration_ms) const {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << to_json(sim_duration_ms).dump(2);
    return true;
}

bool TimelineLogger::write_ascii(const std::string& path,
                                  Timestamp   bin_width_ms,
                                  std::size_t lane_width) const {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << to_ascii(bin_width_ms, lane_width);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Reset
// ─────────────────────────────────────────────────────────────────────────────

void TimelineLogger::reset() noexcept {
    entries_.clear();
    max_time_ms_ = 0;
}

} // namespace uav_pqc::sim
