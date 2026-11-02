// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file event_scheduler.hpp
 * @brief Discrete-event scheduler for the UAV-PQC simulation framework.
 *
 * Provides a priority-queue-based virtual-time event engine.  All protocol
 * timer operations (retransmission, handshake timeout, TreeKEM rekey,
 * session expiry, heartbeat) are expressed as scheduled events on the
 * virtual monotonic clock.  sleep() is never used.
 *
 * Design goals:
 *  - Deterministic replay: reset(seed) + same event sequence = identical output
 *  - O(log n) schedule, O(1) cancel (lazy deletion)
 *  - Periodic events: auto-reschedule via schedule_periodic()
 *  - Priority levels: Critical events always fire before Normal at the same tick
 *  - Tag strings: human-readable labels for timeline visualization
 */

#include "uav_pqc/common/types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// EventId — opaque cancellation handle
// ─────────────────────────────────────────────────────────────────────────────

using EventId = std::uint64_t;

/// Sentinel representing an invalid / already-cancelled event.
inline constexpr EventId kInvalidEventId = 0;

// ─────────────────────────────────────────────────────────────────────────────
// EventPriority — tie-breaking when multiple events fire at the same virtual ms
// ─────────────────────────────────────────────────────────────────────────────

enum class EventPriority : std::uint8_t {
    Low      = 0,
    Normal   = 1,
    High     = 2,
    Critical = 3,
};

// ─────────────────────────────────────────────────────────────────────────────
// Event — internal node stored in the priority queue
// ─────────────────────────────────────────────────────────────────────────────

struct Event {
    Timestamp     fire_time_ms;          ///< Virtual time at which the event fires
    std::uint64_t seq_id;               ///< Monotonic sequence for stable ordering
    EventPriority priority;
    EventId       id;                   ///< Cancellation handle
    std::function<void()> callback;
    std::string   tag;                  ///< Human-readable label for timeline

    /// Min-heap by (fire_time_ms ASC, priority DESC, seq_id ASC).
    bool operator>(const Event& other) const noexcept {
        if (fire_time_ms != other.fire_time_ms)
            return fire_time_ms > other.fire_time_ms;
        if (priority != other.priority)
            return priority < other.priority;           // higher priority = lower comparand
        return seq_id > other.seq_id;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// FireRecord — lightweight record emitted after every event fires
// ─────────────────────────────────────────────────────────────────────────────

struct FireRecord {
    Timestamp   fire_time_ms;
    EventId     id;
    std::string tag;
};

// ─────────────────────────────────────────────────────────────────────────────
// EventScheduler
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Single-threaded discrete-event simulation engine.
 *
 * All time values are in virtual milliseconds.  The scheduler never sleeps;
 * it processes events in virtual-time order by draining the priority queue.
 *
 * Thread safety: NOT thread-safe.  Use exclusively from the simulation thread.
 */
class EventScheduler {
public:
    /// Callback type for fire-record observers (e.g. TimelineLogger).
    using FireObserver = std::function<void(const FireRecord&)>;

    explicit EventScheduler(std::uint64_t rng_seed = 42) noexcept;
    ~EventScheduler() = default;

    EventScheduler(const EventScheduler&)            = delete;
    EventScheduler& operator=(const EventScheduler&) = delete;
    EventScheduler(EventScheduler&&)                 = default;
    EventScheduler& operator=(EventScheduler&&)      = default;

    // ── Scheduling ────────────────────────────────────────────────────────────

    /**
     * @brief Schedule a one-shot event at an absolute virtual time.
     * @param fire_ms   Absolute virtual time (ms) when the callback fires.
     * @param callback  Callable invoked at fire_ms.
     * @param tag       Human-readable label for timeline/debugging.
     * @param priority  Tie-breaking priority when multiple events share fire_ms.
     * @return          Opaque EventId suitable for cancel().
     */
    [[nodiscard]] EventId schedule(Timestamp             fire_ms,
                                   std::function<void()> callback,
                                   std::string           tag      = "",
                                   EventPriority         priority = EventPriority::Normal);

    /**
     * @brief Schedule a one-shot event relative to the current virtual time.
     * @param delay_ms  Delay in ms from now_ms().
     */
    [[nodiscard]] EventId schedule_after(Timestamp             delay_ms,
                                          std::function<void()> callback,
                                          std::string           tag      = "",
                                          EventPriority         priority = EventPriority::Normal);

    /**
     * @brief Schedule a recurring event that fires every interval_ms.
     *
     * The callback is rescheduled automatically after each fire.  Cancel
     * the returned EventId to stop the periodic chain.  The EventId
     * returned refers to the *current* pending instance; after each fire
     * a new EventId is generated (the old one becomes invalid).  Use a
     * shared cancellation flag inside the callback for robust cancellation.
     *
     * @param first_fire_ms  Absolute virtual time of the first fire.
     * @param interval_ms    Interval between subsequent fires.
     */
    [[nodiscard]] EventId schedule_periodic(Timestamp             first_fire_ms,
                                             Timestamp             interval_ms,
                                             std::function<void()> callback,
                                             std::string           tag      = "",
                                             EventPriority         priority = EventPriority::Normal);

    // ── Cancellation ──────────────────────────────────────────────────────────

    /**
     * @brief Cancel a pending event (O(1) lazy deletion).
     * @return true if the event was pending and is now cancelled;
     *         false if it had already fired or was invalid.
     */
    bool cancel(EventId id) noexcept;

    // ── Execution ─────────────────────────────────────────────────────────────

    /**
     * @brief Fire all events whose fire_time_ms ≤ until_ms.
     *
     * After returning, now_ms() == until_ms.
     * @return Number of events fired (excluding cancelled ones).
     */
    std::uint64_t run_until(Timestamp until_ms);

    /**
     * @brief Drain the entire event queue (fires all remaining events).
     * @return Total events fired.
     */
    std::uint64_t run_all();

    /**
     * @brief Fire exactly one event (the earliest pending).
     * @return true if an event was fired; false if the queue is empty.
     */
    bool step();

    // ── Introspection ─────────────────────────────────────────────────────────

    /// Current virtual clock value (ms).
    [[nodiscard]] Timestamp now_ms() const noexcept { return current_time_ms_; }

    /// Next scheduled event time, or nullopt if the queue is empty.
    [[nodiscard]] std::optional<Timestamp> next_event_time() const noexcept;

    /// Total events pending (including cancelled-but-not-yet-popped).
    [[nodiscard]] std::size_t pending_count() const noexcept { return queue_.size(); }

    /// Total events fired since construction or last reset().
    [[nodiscard]] std::uint64_t total_fired() const noexcept { return total_fired_; }

    // ── Deterministic replay ──────────────────────────────────────────────────

    /**
     * @brief Reset the scheduler to time 0 with a new RNG seed.
     *
     * Clears the event queue and all cancellation state.  All EventIds
     * from before the reset are implicitly invalid.
     */
    void reset(std::uint64_t rng_seed = 42) noexcept;

    // ── Observer ──────────────────────────────────────────────────────────────

    /// Register a callback invoked after every event fires (for timeline logging).
    void set_fire_observer(FireObserver observer) { fire_observer_ = std::move(observer); }

private:
    using EventQueue = std::priority_queue<Event, std::vector<Event>, std::greater<Event>>;

    [[nodiscard]] EventId next_id() noexcept { return ++next_event_id_; }
    [[nodiscard]] std::uint64_t next_seq() noexcept { return next_seq_id_++; }

    Timestamp       current_time_ms_  = 0;
    std::uint64_t   next_event_id_    = 0;
    std::uint64_t   next_seq_id_      = 0;
    std::uint64_t   total_fired_      = 0;
    std::uint64_t   rng_seed_;

    EventQueue                   queue_;
    std::unordered_set<EventId>  cancelled_ids_;   ///< Lazy-deletion set

    /// Alive flags for periodic timer chains (keyed by the latest EventId).
    std::unordered_map<EventId, std::shared_ptr<bool>> periodic_alive_;

    std::optional<FireObserver> fire_observer_;
};

} // namespace uav_pqc::sim
