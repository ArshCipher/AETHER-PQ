// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/sim/timer_manager.hpp"

#include <stdexcept>

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

std::string_view timer_kind_name(TimerKind k) noexcept {
    switch (k) {
        case TimerKind::Retransmit: return "Retransmit";
        case TimerKind::Handshake:  return "Handshake";
        case TimerKind::TreeKem:    return "TreeKem";
        case TimerKind::Session:    return "Session";
        case TimerKind::Heartbeat:  return "Heartbeat";
        case TimerKind::Custom:     return "Custom";
    }
    return "Unknown";
}

Timestamp TimerDefaults::for_kind(TimerKind k) noexcept {
    switch (k) {
        case TimerKind::Retransmit: return kRetransmitMs;
        case TimerKind::Handshake:  return kHandshakeMs;
        case TimerKind::TreeKem:    return kTreeKemMs;
        case TimerKind::Session:    return kSessionMs;
        case TimerKind::Heartbeat:  return kHeartbeatMs;
        case TimerKind::Custom:     return 0;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// TimerManager — constructor
// ─────────────────────────────────────────────────────────────────────────────

TimerManager::TimerManager(EventScheduler& scheduler) noexcept
    : scheduler_(scheduler)
{}

// ─────────────────────────────────────────────────────────────────────────────
// arm()
// ─────────────────────────────────────────────────────────────────────────────

TimerHandle TimerManager::arm(TimerSpec spec) {
    // Resolve default timeout
    Timestamp timeout = (spec.timeout_ms > 0)
                        ? spec.timeout_ms
                        : TimerDefaults::for_kind(spec.kind);

    // Resolve tag
    if (spec.tag.empty()) {
        spec.tag = std::string(timer_kind_name(spec.kind));
    }

    const TimerKind kind        = spec.kind;
    const uint8_t   kind_idx    = static_cast<uint8_t>(kind);
    auto            on_fire     = std::move(spec.on_fire);
    auto            on_expire   = std::move(spec.on_expire);
    const uint32_t  max_fires   = spec.max_fires;
    std::string     tag         = spec.tag;
    EventPriority   prio        = spec.priority;
    const Timestamp interval    = spec.interval_ms;

    // Shared fire counter for max_fires enforcement
    auto fire_count = std::make_shared<uint32_t>(0);

    EventId id = kInvalidEventId;

    if (interval > 0) {
        // ── Periodic timer ─────────────────────────────────────────────────
        Timestamp first_fire = scheduler_.now_ms() + timeout;

        id = scheduler_.schedule_periodic(
            first_fire, interval,
            [this, kind_idx, on_fire, on_expire, max_fires, fire_count]() mutable {
                ++(*fire_count);
                record_fired(static_cast<TimerKind>(kind_idx));

                if (on_fire) on_fire();

                if (max_fires > 0 && *fire_count >= max_fires) {
                    record_expired(static_cast<TimerKind>(kind_idx));
                    if (on_expire) on_expire();
                    // The periodic chain continues, but caller should cancel the handle.
                    // We don't self-cancel here because we don't have the EventId yet.
                }
            },
            tag, prio
        );
    } else {
        // ── One-shot timer ─────────────────────────────────────────────────
        Timestamp fire_ms = scheduler_.now_ms() + timeout;

        if (max_fires > 1) {
            // Simulate multi-shot by building a chain internally.
            // Each shot reschedules with the same timeout.
            auto chain_fn = std::make_shared<std::function<void(uint32_t, Timestamp)>>();
            *chain_fn = [this, kind_idx, on_fire, on_expire, max_fires,
                         fire_count, timeout, prio, tag, chain_fn](
                             uint32_t remaining, Timestamp /*fired_at*/) mutable {
                ++(*fire_count);
                record_fired(static_cast<TimerKind>(kind_idx));
                if (on_fire) on_fire();

                uint32_t new_remaining = remaining - 1;
                if (new_remaining == 0) {
                    record_expired(static_cast<TimerKind>(kind_idx));
                    if (on_expire) on_expire();
                } else {
                    Timestamp next = scheduler_.now_ms() + timeout;
                    scheduler_.schedule(
                        next,
                        [chain_fn, new_remaining, next]() {
                            (*chain_fn)(new_remaining, next);
                        },
                        tag, static_cast<EventPriority>(prio)
                    );
                }
            };

            id = scheduler_.schedule(
                fire_ms,
                [chain_fn, max_fires, fire_ms]() { (*chain_fn)(max_fires, fire_ms); },
                tag, prio
            );
        } else {
            // Simple one-shot
            id = scheduler_.schedule(
                fire_ms,
                [this, kind_idx, on_fire, on_expire]() mutable {
                    record_fired(static_cast<TimerKind>(kind_idx));
                    if (on_fire) on_fire();
                    record_expired(static_cast<TimerKind>(kind_idx));
                    if (on_expire) on_expire();
                },
                tag, prio
            );
        }
    }

    record_armed(kind);
    active_[kind_idx]++;

    return TimerHandle(&scheduler_, id, kind);
}

// ─────────────────────────────────────────────────────────────────────────────
// rearm()
// ─────────────────────────────────────────────────────────────────────────────

void TimerManager::rearm(TimerHandle& handle, Timestamp new_timeout_ms) {
    if (!handle.active()) return;

    TimerKind kind = handle.kind();
    handle.cancel();
    // Record the cancel (already done inside TimerHandle::cancel → EventScheduler::cancel)
    record_cancelled(kind);
    if (active_[static_cast<uint8_t>(kind)] > 0)
        active_[static_cast<uint8_t>(kind)]--;

    TimerSpec spec;
    spec.kind       = kind;
    spec.timeout_ms = new_timeout_ms;
    handle = arm(std::move(spec));
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience factories
// ─────────────────────────────────────────────────────────────────────────────

TimerHandle TimerManager::retransmit(std::function<void()> on_fire,
                                      std::function<void()> on_expire,
                                      Timestamp             timeout_ms,
                                      std::uint32_t         max_fires) {
    return arm(TimerSpec{
        .kind       = TimerKind::Retransmit,
        .timeout_ms = timeout_ms,
        .interval_ms= 0,
        .max_fires  = max_fires,
        .on_fire    = std::move(on_fire),
        .on_expire  = std::move(on_expire),
        .priority   = EventPriority::High,
    });
}

TimerHandle TimerManager::handshake(std::function<void()> on_expire,
                                     Timestamp             timeout_ms) {
    return arm(TimerSpec{
        .kind       = TimerKind::Handshake,
        .timeout_ms = timeout_ms,
        .interval_ms= 0,
        .max_fires  = 1,
        .on_fire    = {},
        .on_expire  = std::move(on_expire),
        .priority   = EventPriority::High,
    });
}

TimerHandle TimerManager::treekem(std::function<void()> on_expire,
                                   Timestamp             timeout_ms) {
    return arm(TimerSpec{
        .kind       = TimerKind::TreeKem,
        .timeout_ms = timeout_ms,
        .interval_ms= 0,
        .max_fires  = 1,
        .on_fire    = {},
        .on_expire  = std::move(on_expire),
        .priority   = EventPriority::Normal,
    });
}

TimerHandle TimerManager::session(std::function<void()> on_expire,
                                   Timestamp             timeout_ms) {
    return arm(TimerSpec{
        .kind       = TimerKind::Session,
        .timeout_ms = timeout_ms,
        .interval_ms= 0,
        .max_fires  = 1,
        .on_fire    = {},
        .on_expire  = std::move(on_expire),
        .priority   = EventPriority::Low,
    });
}

TimerHandle TimerManager::heartbeat(std::function<void()> on_fire,
                                     Timestamp             interval_ms) {
    if (interval_ms == 0) interval_ms = TimerDefaults::kHeartbeatMs;
    return arm(TimerSpec{
        .kind        = TimerKind::Heartbeat,
        .timeout_ms  = interval_ms,
        .interval_ms = interval_ms,
        .max_fires   = 0,                 // unlimited
        .on_fire     = std::move(on_fire),
        .on_expire   = {},
        .priority    = EventPriority::Low,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────────────

const TimerStats& TimerManager::stats(TimerKind k) const noexcept {
    return stats_[static_cast<uint8_t>(k)];
}

std::vector<TimerStats> TimerManager::all_stats() const {
    return {stats_[0], stats_[1], stats_[2], stats_[3], stats_[4], stats_[5]};
}

std::size_t TimerManager::active_count(TimerKind k) const noexcept {
    return active_[static_cast<uint8_t>(k)];
}

std::size_t TimerManager::total_active() const noexcept {
    std::size_t total = 0;
    for (auto a : active_) total += a;
    return total;
}

// ─────────────────────────────────────────────────────────────────────────────
// Private stat helpers
// ─────────────────────────────────────────────────────────────────────────────

void TimerManager::record_armed(TimerKind k) {
    stats_[static_cast<uint8_t>(k)].armed++;
}

void TimerManager::record_fired(TimerKind k) {
    stats_[static_cast<uint8_t>(k)].fired++;
}

void TimerManager::record_expired(TimerKind k) {
    auto idx = static_cast<uint8_t>(k);
    stats_[idx].expired++;
    if (active_[idx] > 0) active_[idx]--;
}

void TimerManager::record_cancelled(TimerKind k) {
    stats_[static_cast<uint8_t>(k)].cancelled++;
}

} // namespace uav_pqc::sim
