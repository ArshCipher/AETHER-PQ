// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/sim/simulation_context.hpp"

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

SimulationContext::SimulationContext(SimulationConfig config)
    : config_(std::move(config))
    , scheduler_(config_.rng_seed)
    , timer_mgr_(std::make_unique<TimerManager>(scheduler_))
{
    // Wire the fire observer for automatic timeline logging
    if (config_.auto_log_events) {
        scheduler_.set_fire_observer([this](const FireRecord& rec) {
            if (rec.tag.empty()) return;
            timeline_.record(
                rec.fire_time_ms,
                config_.default_node_id,
                TimelineEventKind::Custom,
                rec.tag
            );
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduling
// ─────────────────────────────────────────────────────────────────────────────

EventId SimulationContext::schedule_event(Timestamp             fire_ms,
                                           std::function<void()> callback,
                                           std::string           tag,
                                           EventPriority         priority) {
    return scheduler_.schedule(fire_ms, std::move(callback), std::move(tag), priority);
}

EventId SimulationContext::schedule_after(Timestamp             delay_ms,
                                           std::function<void()> callback,
                                           std::string           tag,
                                           EventPriority         priority) {
    return scheduler_.schedule_after(delay_ms, std::move(callback), std::move(tag), priority);
}

bool SimulationContext::cancel_event(EventId id) noexcept {
    return scheduler_.cancel(id);
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution
// ─────────────────────────────────────────────────────────────────────────────

std::uint64_t SimulationContext::advance_to(Timestamp until_ms) {
    return scheduler_.run_until(until_ms);
}

std::uint64_t SimulationContext::run_all() {
    return scheduler_.run_all();
}

bool SimulationContext::step() {
    return scheduler_.step();
}

// ─────────────────────────────────────────────────────────────────────────────
// Clock introspection
// ─────────────────────────────────────────────────────────────────────────────

Timestamp SimulationContext::now_ms() const noexcept {
    return scheduler_.now_ms();
}

std::optional<Timestamp> SimulationContext::next_event_time() const noexcept {
    return scheduler_.next_event_time();
}

std::uint64_t SimulationContext::total_events_fired() const noexcept {
    return scheduler_.total_fired();
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic replay
// ─────────────────────────────────────────────────────────────────────────────

void SimulationContext::reset(std::optional<std::uint64_t> new_seed) {
    std::uint64_t seed = new_seed.value_or(config_.rng_seed);
    scheduler_.reset(seed);
    // Recreate timer manager (all outstanding handles become invalid)
    timer_mgr_ = std::make_unique<TimerManager>(scheduler_);
    timeline_.reset();
    finalized_ = false;

    // Rewire fire observer
    if (config_.auto_log_events) {
        scheduler_.set_fire_observer([this](const FireRecord& rec) {
            if (rec.tag.empty()) return;
            timeline_.record(
                rec.fire_time_ms,
                config_.default_node_id,
                TimelineEventKind::Custom,
                rec.tag
            );
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Finalization
// ─────────────────────────────────────────────────────────────────────────────

void SimulationContext::finalize() {
    if (finalized_) return;
    finalized_ = true;
    // Nothing else to flush currently; the timeline records events as they fire.
}

} // namespace uav_pqc::sim
