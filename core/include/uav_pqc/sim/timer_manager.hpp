// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file timer_manager.hpp
 * @brief Named protocol timer factory built on top of EventScheduler.
 *
 * Provides RAII TimerHandle objects for six named timer kinds:
 *   Retransmit   — per-stream fragment retransmission (1 s, max 5 fires)
 *   Handshake    — overall handshake timeout (10 s, max 1 fire)
 *   TreeKem      — TreeKEM rekey deadline (30 s, max 1 fire)
 *   Session      — session lifetime / re-establishment trigger (1 h, max 1 fire)
 *   Heartbeat    — keep-alive / tick driver (5 s, periodic)
 *   Custom       — caller-defined one-shot or periodic timer
 *
 * Usage:
 * @code
 *   TimerManager timers(scheduler);
 *
 *   // Arm a handshake timeout; auto-cancels on scope exit
 *   auto hs_timer = timers.arm({
 *       .kind       = TimerKind::Handshake,
 *       .timeout_ms = 10'000,
 *       .on_fire    = [&]{ handle_handshake_timeout(); },
 *   });
 *
 *   // Cancel explicitly
 *   hs_timer.cancel();
 * @endcode
 */

#include "uav_pqc/sim/event_scheduler.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// TimerKind
// ─────────────────────────────────────────────────────────────────────────────

enum class TimerKind : std::uint8_t {
    Retransmit = 0,  ///< Fragment retransmission timer
    Handshake  = 1,  ///< PQ hybrid handshake overall timeout
    TreeKem    = 2,  ///< TreeKEM rekey / enrollment deadline
    Session    = 3,  ///< Session lifetime expiry
    Heartbeat  = 4,  ///< Periodic keep-alive / network-manager tick driver
    Custom     = 5,  ///< Caller-defined, no default timeout
};

[[nodiscard]] std::string_view timer_kind_name(TimerKind k) noexcept;

// ─────────────────────────────────────────────────────────────────────────────
// Default timeouts per kind
// ─────────────────────────────────────────────────────────────────────────────

struct TimerDefaults {
    static constexpr Timestamp kRetransmitMs = 1'000;
    static constexpr Timestamp kHandshakeMs  = 10'000;
    static constexpr Timestamp kTreeKemMs    = 30'000;
    static constexpr Timestamp kSessionMs    = 3'600'000;
    static constexpr Timestamp kHeartbeatMs  = 5'000;

    [[nodiscard]] static Timestamp for_kind(TimerKind k) noexcept;
};

// ─────────────────────────────────────────────────────────────────────────────
// TimerSpec — describes a timer to be armed
// ─────────────────────────────────────────────────────────────────────────────

struct TimerSpec {
    TimerKind             kind        = TimerKind::Custom;

    /// Timeout from now (ms).  0 = use the default for this kind.
    Timestamp             timeout_ms  = 0;

    /// For periodic timers: how often to re-fire after the first fire.
    /// 0 = one-shot.
    Timestamp             interval_ms = 0;

    /// Maximum number of times on_fire may be called before on_expire fires.
    /// 0 = unlimited (use with interval_ms > 0 for pure periodic).
    std::uint32_t         max_fires   = 0;

    /// Called each time the timer fires (before max_fires is exhausted).
    std::function<void()> on_fire;

    /// Called when max_fires is exhausted (timeout expired without success).
    /// Not called for timers with max_fires == 0.
    std::function<void()> on_expire;

    /// Human-readable label; defaults to timer_kind_name(kind) if empty.
    std::string           tag;

    EventPriority         priority    = EventPriority::Normal;
};

// ─────────────────────────────────────────────────────────────────────────────
// TimerHandle — RAII cancellation handle
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief RAII wrapper that automatically cancels a pending timer on destruction.
 *
 * Movable but not copyable.  Default-constructed handle is inactive.
 */
class TimerHandle {
public:
    TimerHandle() = default;
    ~TimerHandle() { cancel(); }

    TimerHandle(const TimerHandle&)            = delete;
    TimerHandle& operator=(const TimerHandle&) = delete;

    TimerHandle(TimerHandle&& other) noexcept
        : scheduler_(other.scheduler_)
        , event_id_(other.event_id_)
        , kind_(other.kind_)
    {
        other.scheduler_ = nullptr;
        other.event_id_  = kInvalidEventId;
    }

    TimerHandle& operator=(TimerHandle&& other) noexcept {
        if (this != &other) {
            cancel();
            scheduler_ = other.scheduler_;
            event_id_  = other.event_id_;
            kind_      = other.kind_;
            other.scheduler_ = nullptr;
            other.event_id_  = kInvalidEventId;
        }
        return *this;
    }

    /// Cancel the pending timer (idempotent; safe to call on inactive handle).
    void cancel() noexcept {
        if (scheduler_ && event_id_ != kInvalidEventId) {
            scheduler_->cancel(event_id_);
            event_id_ = kInvalidEventId;
        }
    }

    /// True if the handle refers to a pending (not yet cancelled) timer.
    [[nodiscard]] bool active() const noexcept {
        return scheduler_ != nullptr && event_id_ != kInvalidEventId;
    }

    [[nodiscard]] EventId    event_id() const noexcept { return event_id_; }
    [[nodiscard]] TimerKind  kind()     const noexcept { return kind_; }

private:
    friend class TimerManager;

    TimerHandle(EventScheduler* sched, EventId id, TimerKind k)
        : scheduler_(sched), event_id_(id), kind_(k) {}

    EventScheduler* scheduler_ = nullptr;
    EventId         event_id_  = kInvalidEventId;
    TimerKind       kind_      = TimerKind::Custom;
};

// ─────────────────────────────────────────────────────────────────────────────
// TimerStats — per-kind aggregate counters
// ─────────────────────────────────────────────────────────────────────────────

struct TimerStats {
    TimerKind     kind;
    std::uint64_t armed    = 0;  ///< Total timers armed
    std::uint64_t fired    = 0;  ///< Total individual fire callbacks invoked
    std::uint64_t expired  = 0;  ///< Total timers that hit on_expire
    std::uint64_t cancelled= 0;  ///< Total timers cancelled before expiry
};

// ─────────────────────────────────────────────────────────────────────────────
// TimerManager
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Factory and lifecycle manager for all named protocol timers.
 *
 * Wraps EventScheduler to provide named-timer semantics with RAII handles,
 * per-kind statistics, and default timeouts.
 *
 * Thread safety: NOT thread-safe (mirrors EventScheduler).
 */
class TimerManager {
public:
    explicit TimerManager(EventScheduler& scheduler) noexcept;
    ~TimerManager() = default;

    TimerManager(const TimerManager&)            = delete;
    TimerManager& operator=(const TimerManager&) = delete;
    TimerManager(TimerManager&&)                 = delete;
    TimerManager& operator=(TimerManager&&)      = delete;

    /**
     * @brief Arm a timer according to spec.
     *
     * If spec.timeout_ms == 0, the default for spec.kind is used.
     * If spec.tag is empty, timer_kind_name(spec.kind) is used.
     *
     * @return RAII TimerHandle; cancels automatically on destruction.
     */
    [[nodiscard]] TimerHandle arm(TimerSpec spec);

    /**
     * @brief Rearm an existing timer with a new timeout.
     *
     * Cancels the old timer, arms a new one with the same spec but updated
     * timeout.  The handle is updated in-place.
     */
    void rearm(TimerHandle& handle, Timestamp new_timeout_ms);

    // ── Convenience factory methods ───────────────────────────────────────────

    /// One-shot retransmit timer (1 s default).
    [[nodiscard]] TimerHandle retransmit(std::function<void()> on_fire,
                                         std::function<void()> on_expire = {},
                                         Timestamp timeout_ms = 0,
                                         std::uint32_t max_fires = 5);

    /// One-shot handshake timeout (10 s default).
    [[nodiscard]] TimerHandle handshake(std::function<void()> on_expire,
                                         Timestamp timeout_ms = 0);

    /// One-shot TreeKEM rekey deadline (30 s default).
    [[nodiscard]] TimerHandle treekem(std::function<void()> on_expire,
                                       Timestamp timeout_ms = 0);

    /// One-shot session expiry timer (1 h default).
    [[nodiscard]] TimerHandle session(std::function<void()> on_expire,
                                       Timestamp timeout_ms = 0);

    /// Periodic heartbeat (5 s default interval, unlimited fires).
    [[nodiscard]] TimerHandle heartbeat(std::function<void()> on_fire,
                                         Timestamp interval_ms = 0);

    // ── Statistics ────────────────────────────────────────────────────────────

    [[nodiscard]] const TimerStats& stats(TimerKind k) const noexcept;
    [[nodiscard]] std::vector<TimerStats> all_stats() const;

    /// Number of currently active timers of the given kind.
    [[nodiscard]] std::size_t active_count(TimerKind k) const noexcept;

    /// Total active timers across all kinds.
    [[nodiscard]] std::size_t total_active() const noexcept;

private:
    void record_armed(TimerKind k);
    void record_fired(TimerKind k);
    void record_expired(TimerKind k);
    void record_cancelled(TimerKind k);

    EventScheduler& scheduler_;

    // Per-kind statistics (indexed by TimerKind cast to uint8_t)
    TimerStats stats_[6]{
        {TimerKind::Retransmit},
        {TimerKind::Handshake},
        {TimerKind::TreeKem},
        {TimerKind::Session},
        {TimerKind::Heartbeat},
        {TimerKind::Custom},
    };

    // Count of live handles per kind (incremented on arm, decremented on cancel/expire)
    std::uint32_t active_[6]{};
};

} // namespace uav_pqc::sim
