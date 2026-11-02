// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file simulation_context.hpp
 * @brief Top-level façade binding EventScheduler, TimerManager, and
 *        TimelineLogger into a unified simulation environment.
 *
 * SimulationContext is the primary object constructed by simulation tools
 * (standalone_sim, ns3_sim) and test harnesses.  It owns the virtual clock,
 * all timers, and the event log.  Protocol nodes schedule operations through
 * their references to this context rather than using sleep() or real-time
 * clocks.
 *
 * Usage:
 * @code
 *   SimulationConfig cfg;
 *   cfg.rng_seed   = 42;
 *   cfg.wall_clock = false;   // pure virtual-time simulation
 *
 *   SimulationContext ctx(cfg);
 *
 *   // Schedule an event
 *   ctx.schedule_event(1000, [&]{ run_handshake(); }, "Handshake");
 *
 *   // Arm a handshake timeout timer
 *   auto hs = ctx.timers().handshake([&]{ handle_timeout(); });
 *
 *   // Run the simulation until all events are drained
 *   ctx.run_all();
 *
 *   // Export timeline
 *   ctx.timeline().write_json("timeline.json");
 *   ctx.timeline().write_ascii("timeline.txt");
 * @endcode
 */

#include "uav_pqc/sim/event_scheduler.hpp"
#include "uav_pqc/sim/timer_manager.hpp"
#include "uav_pqc/sim/timeline_logger.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// SimulationConfig
// ─────────────────────────────────────────────────────────────────────────────

struct SimulationConfig {
    /// RNG seed for the EventScheduler and ChannelEmulator — controls determinism.
    std::uint64_t rng_seed = 42;

    /// If true, the scheduler uses wall-clock time instead of advancing
    /// the virtual clock (useful for hardware-in-the-loop).
    /// In this mode run_all() is a no-op; the caller drives tick().
    bool wall_clock = false;

    /// If true, every scheduled event is automatically recorded in the
    /// TimelineLogger with its tag as the label.
    bool auto_log_events = true;

    /// Node ID to use as the "current node" for automatic timeline entries
    /// (hex string, e.g. "GCS" or "0001...").
    std::string default_node_id = "SIM";

    // ── Default timer overrides (0 = use TimerDefaults) ───────────────────────
    Timestamp retransmit_ms = 0;
    Timestamp handshake_ms  = 0;
    Timestamp treekem_ms    = 0;
    Timestamp session_ms    = 0;
    Timestamp heartbeat_ms  = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// SimulationContext
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Unified simulation environment: clock + events + timers + timeline.
 *
 * Owns:
 *   - EventScheduler (virtual clock + priority queue)
 *   - TimerManager   (named protocol timers)
 *   - TimelineLogger (post-run visualization)
 *
 * NOT thread-safe.  All calls must originate from the simulation thread.
 */
class SimulationContext {
public:
    explicit SimulationContext(SimulationConfig config = {});
    ~SimulationContext() = default;

    SimulationContext(const SimulationContext&)            = delete;
    SimulationContext& operator=(const SimulationContext&) = delete;
    SimulationContext(SimulationContext&&)                 = default;
    SimulationContext& operator=(SimulationContext&&)      = default;

    // ── Scheduling ─────────────────────────────────────────────────────────────

    /**
     * @brief Schedule a one-shot callback at absolute virtual time fire_ms.
     *
     * If auto_log_events is enabled, the event is recorded in the timeline.
     *
     * @param fire_ms   Absolute virtual fire time.
     * @param callback  Callable to invoke at fire_ms.
     * @param tag       Human-readable label (used in timeline and logs).
     * @param priority  Tie-breaking priority.
     * @return          EventId for optional cancellation.
     */
    [[nodiscard]] EventId schedule_event(Timestamp             fire_ms,
                                          std::function<void()> callback,
                                          std::string           tag      = "",
                                          EventPriority         priority = EventPriority::Normal);

    /**
     * @brief Schedule a one-shot callback delay_ms from now.
     */
    [[nodiscard]] EventId schedule_after(Timestamp             delay_ms,
                                          std::function<void()> callback,
                                          std::string           tag      = "",
                                          EventPriority         priority = EventPriority::Normal);

    /**
     * @brief Cancel a pending event by ID.
     * @return true if cancelled; false if already fired or invalid.
     */
    bool cancel_event(EventId id) noexcept;

    // ── Execution ─────────────────────────────────────────────────────────────

    /**
     * @brief Advance the virtual clock and fire all events up to until_ms.
     * @return Number of events fired.
     */
    std::uint64_t advance_to(Timestamp until_ms);

    /**
     * @brief Drain the entire event queue (fires all scheduled events).
     * @return Total events fired.
     */
    std::uint64_t run_all();

    /**
     * @brief Fire the next single event.
     * @return true if an event was fired.
     */
    bool step();

    // ── Timer management ──────────────────────────────────────────────────────

    [[nodiscard]] TimerManager& timers() noexcept { return *timer_mgr_; }
    [[nodiscard]] const TimerManager& timers() const noexcept { return *timer_mgr_; }

    // ── Timeline ──────────────────────────────────────────────────────────────

    [[nodiscard]] TimelineLogger& timeline() noexcept { return timeline_; }
    [[nodiscard]] const TimelineLogger& timeline() const noexcept { return timeline_; }

    // ── Clock ─────────────────────────────────────────────────────────────────

    [[nodiscard]] Timestamp now_ms() const noexcept;
    [[nodiscard]] std::optional<Timestamp> next_event_time() const noexcept;
    [[nodiscard]] std::uint64_t total_events_fired() const noexcept;

    // ── Configuration ─────────────────────────────────────────────────────────

    [[nodiscard]] const SimulationConfig& config() const noexcept { return config_; }

    /// Update the "current node" used for automatic timeline entries.
    void set_node_context(std::string node_id_hex) noexcept {
        config_.default_node_id = std::move(node_id_hex);
    }

    // ── Deterministic replay ──────────────────────────────────────────────────

    /**
     * @brief Reset the context to time 0 (new run with the same or different seed).
     *
     * Clears the event queue, all timers, and the timeline log.
     * Any existing TimerHandles become invalid after this call.
     */
    void reset(std::optional<std::uint64_t> new_seed = std::nullopt);

    // ── Finalization ──────────────────────────────────────────────────────────

    /**
     * @brief Call after run_all() completes to finalize per-run metadata.
     *
     * Records final sim_duration in the timeline header.  Safe to call
     * multiple times (idempotent).
     */
    void finalize();

private:
    SimulationConfig              config_;
    EventScheduler                scheduler_;
    std::unique_ptr<TimerManager> timer_mgr_;
    TimelineLogger                timeline_;
    bool                          finalized_ = false;
};

} // namespace uav_pqc::sim
