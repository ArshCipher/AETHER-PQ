// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/sim/event_scheduler.hpp"

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

EventScheduler::EventScheduler(std::uint64_t rng_seed) noexcept
    : rng_seed_(rng_seed)
{}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduling
// ─────────────────────────────────────────────────────────────────────────────

EventId EventScheduler::schedule(Timestamp             fire_ms,
                                  std::function<void()> callback,
                                  std::string           tag,
                                  EventPriority         priority) {
    EventId id  = next_id();
    Event   ev;
    ev.fire_time_ms = fire_ms;
    ev.seq_id       = next_seq();
    ev.priority     = priority;
    ev.id           = id;
    ev.callback     = std::move(callback);
    ev.tag          = std::move(tag);
    queue_.push(std::move(ev));
    return id;
}

EventId EventScheduler::schedule_after(Timestamp             delay_ms,
                                        std::function<void()> callback,
                                        std::string           tag,
                                        EventPriority         priority) {
    return schedule(current_time_ms_ + delay_ms,
                    std::move(callback),
                    std::move(tag),
                    priority);
}

EventId EventScheduler::schedule_periodic(Timestamp             first_fire_ms,
                                           Timestamp             interval_ms,
                                           std::function<void()> callback,
                                           std::string           tag,
                                           EventPriority         priority) {
    // We need a shared cancellation flag so the self-rescheduling lambda can
    // detect when the caller has cancelled this periodic chain.
    // Strategy: each periodic fire reschedules using the same interval.
    // The caller cancels by cancelling the returned (current) EventId.
    // We use a shared_ptr<bool> as a live/dead flag so the closed-over
    // lambda can check it without a dangling reference.
    auto alive = std::make_shared<bool>(true);
    std::string tag_copy = tag;

    // Forward-declare so the lambda can capture it.
    // We use a recursive lambda via shared_ptr<std::function<...>>.
    auto self_fn = std::make_shared<std::function<void(Timestamp)>>();

    *self_fn = [this, interval_ms, callback, tag_copy, priority, alive,
                self_fn](Timestamp next_fire) mutable {
        if (!*alive) return;
        // Fire the user callback
        callback();
        if (!*alive) return;
        // Reschedule
        Timestamp next_next = next_fire + interval_ms;
        schedule(next_next,
                 [self_fn, next_next]() { (*self_fn)(next_next); },
                 tag_copy,
                 priority);
    };

    EventId id = schedule(first_fire_ms,
                          [self_fn, first_fire_ms]() { (*self_fn)(first_fire_ms); },
                          std::move(tag),
                          priority);

    // Tie the alive flag to the EventId: if the user cancels id, we also
    // set *alive = false.  We do this by wrapping cancel().
    // Since cancel() uses the cancelled_ids_ set and the self_fn checks alive,
    // the combination correctly stops the chain.
    //
    // We store the alive ptr keyed by EventId so cancel() can clear it.
    periodic_alive_[id] = alive;
    return id;
}

// ─────────────────────────────────────────────────────────────────────────────
// Cancellation
// ─────────────────────────────────────────────────────────────────────────────

bool EventScheduler::cancel(EventId id) noexcept {
    if (id == kInvalidEventId) return false;
    if (cancelled_ids_.count(id)) return false;   // already cancelled
    cancelled_ids_.insert(id);

    // If this is a periodic timer, kill the alive flag so future reschedules stop.
    auto it = periodic_alive_.find(id);
    if (it != periodic_alive_.end()) {
        if (it->second) *(it->second) = false;
        periodic_alive_.erase(it);
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution
// ─────────────────────────────────────────────────────────────────────────────

std::uint64_t EventScheduler::run_until(Timestamp until_ms) {
    std::uint64_t fired = 0;
    while (!queue_.empty()) {
        const Event& top = queue_.top();
        if (top.fire_time_ms > until_ms) break;

        Event ev = queue_.top();
        queue_.pop();

        // Lazy deletion check
        if (cancelled_ids_.count(ev.id)) {
            cancelled_ids_.erase(ev.id);
            continue;
        }

        current_time_ms_ = ev.fire_time_ms;
        ev.callback();
        ++total_fired_;
        ++fired;

        if (fire_observer_) {
            (*fire_observer_)(FireRecord{ev.fire_time_ms, ev.id, ev.tag});
        }
    }
    current_time_ms_ = until_ms;
    return fired;
}

std::uint64_t EventScheduler::run_all() {
    std::uint64_t fired = 0;
    while (!queue_.empty()) {
        Event ev = queue_.top();
        queue_.pop();

        if (cancelled_ids_.count(ev.id)) {
            cancelled_ids_.erase(ev.id);
            continue;
        }

        current_time_ms_ = ev.fire_time_ms;
        ev.callback();
        ++total_fired_;
        ++fired;

        if (fire_observer_) {
            (*fire_observer_)(FireRecord{ev.fire_time_ms, ev.id, ev.tag});
        }
    }
    return fired;
}

bool EventScheduler::step() {
    while (!queue_.empty()) {
        Event ev = queue_.top();
        queue_.pop();

        if (cancelled_ids_.count(ev.id)) {
            cancelled_ids_.erase(ev.id);
            continue;
        }

        current_time_ms_ = ev.fire_time_ms;
        ev.callback();
        ++total_fired_;

        if (fire_observer_) {
            (*fire_observer_)(FireRecord{ev.fire_time_ms, ev.id, ev.tag});
        }
        return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Introspection
// ─────────────────────────────────────────────────────────────────────────────

std::optional<Timestamp> EventScheduler::next_event_time() const noexcept {
    if (queue_.empty()) return std::nullopt;
    return queue_.top().fire_time_ms;
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic replay
// ─────────────────────────────────────────────────────────────────────────────

void EventScheduler::reset(std::uint64_t rng_seed) noexcept {
    // Clear the queue by swapping with an empty one
    EventQueue empty;
    std::swap(queue_, empty);

    cancelled_ids_.clear();
    periodic_alive_.clear();
    current_time_ms_ = 0;
    next_event_id_   = 0;
    next_seq_id_     = 0;
    total_fired_     = 0;
    rng_seed_        = rng_seed;
}

} // namespace uav_pqc::sim
