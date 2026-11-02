// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file session_cache.cpp
 * @brief Bounded session resumption cache with LRU eviction.
 */

#include "uav_pqc/session/session_cache.hpp"
#include "uav_pqc/common/logging.hpp"

#include <algorithm>

namespace uav_pqc::session {

// ── SessionIdHash ─────────────────────────────────────────────────────────────

std::size_t SessionCache::SessionIdHash::operator()(const SessionId& id) const noexcept {
    // FNV-1a on the 16-byte session ID
    std::size_t hash = 14695981039346656037ULL;
    for (const auto byte : id) {
        hash ^= static_cast<std::size_t>(static_cast<std::uint8_t>(byte));
        hash *= 1099511628211ULL;
    }
    return hash;
}

// ── Constructor ───────────────────────────────────────────────────────────────

SessionCache::SessionCache(std::size_t max_entries, Timestamp default_ttl_ms, std::shared_ptr<platform::IClock> clock)
    : max_entries_(max_entries),
      default_ttl_ms_(default_ttl_ms),
      clock_(clock) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    entries_.reserve(max_entries);
}

// ── store ─────────────────────────────────────────────────────────────────────

VoidResult SessionCache::store(Session&& session, Timestamp now_ms, Timestamp ttl_ms) {
    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    const Timestamp effective_ttl = (ttl_ms == 0) ? default_ttl_ms_ : ttl_ms;
    const SessionId sid = session.id();

    if (full()) {
        // Try to evict an expired entry first
        const std::size_t pruned = prune(current_time);
        if (pruned == 0 && full()) {
            // Evict the entry that expires soonest (LRU-approximation)
            SessionId oldest_id{};
            Timestamp oldest_expiry = UINT64_MAX;
            for (const auto& [key, entry] : entries_) {
                const Timestamp expiry = entry.cached_at_ms + entry.ttl_ms;
                if (expiry < oldest_expiry) {
                    oldest_expiry = expiry;
                    oldest_id = key;
                }
            }
            entries_.erase(oldest_id);
            UAV_PQC_LOG_DEBUG("session.cache", "Evicted oldest entry to make room");
        }
    }

    CacheEntry entry{std::move(session), current_time, effective_ttl};
    entries_.emplace(sid, std::move(entry));

    UAV_PQC_LOG_DEBUG("session.cache", "Stored session {} (ttl={}ms entries={})",
                      to_hex(ByteSpan{sid.data(), sid.size()}), effective_ttl, entries_.size());
    return ok();
}

// ── retrieve ──────────────────────────────────────────────────────────────────

Result<Session> SessionCache::retrieve(const SessionId& session_id,
                                        const NodeId& peer_node_id,
                                        Timestamp now_ms) {
    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    auto it = entries_.find(session_id);
    if (it == entries_.end()) {
        return err<Session>(ErrorCode::SessionNotFound,
            "Session not found in resumption cache");
    }

    CacheEntry& entry = it->second;

    // Check TTL
    if (current_time > entry.cached_at_ms + entry.ttl_ms) {
        entries_.erase(it);
        return err<Session>(ErrorCode::SessionExpired, "Cached session has expired");
    }

    // Validate peer identity (anti-hijacking)
    if (entry.session.peer_node_id() != peer_node_id) {
        return err<Session>(ErrorCode::AuthenticationFailed,
            "Session NodeId mismatch — possible hijacking attempt");
    }

    Session s = std::move(entry.session);
    entries_.erase(it);
    UAV_PQC_LOG_INFO("session.cache", "Resumed session {}",
                     to_hex(ByteSpan{session_id.data(), session_id.size()}));
    return ok<Session>(std::move(s));
}

// ── prune ─────────────────────────────────────────────────────────────────────

std::size_t SessionCache::prune(Timestamp now_ms) {
    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    std::size_t evicted = 0;
    auto it = entries_.begin();
    while (it != entries_.end()) {
        if (current_time > it->second.cached_at_ms + it->second.ttl_ms) {
            it = entries_.erase(it);
            ++evicted;
        } else {
            ++it;
        }
    }
    if (evicted > 0) {
        UAV_PQC_LOG_DEBUG("session.cache", "Pruned {} expired entries", evicted);
    }
    return evicted;
}

} // namespace uav_pqc::session
