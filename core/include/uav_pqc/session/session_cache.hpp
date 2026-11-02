// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file session_cache.hpp
 * @brief Session resumption cache.
 *
 * Previously authenticated UAVs that experience a temporary signal drop
 * can resume their session within the cache validity window without a full
 * re-handshake.  This avoids repeated ML-KEM encapsulation operations on
 * the flight controller during signal fades.
 *
 * Cache security properties:
 *  - Each cache entry is bound to a (SessionId, peer NodeId) pair.
 *  - Entries expire after a configurable TTL (default: 60 seconds).
 *  - Expired entries are lazily evicted on lookup and periodically pruned.
 *  - The cache is bounded in size to prevent memory exhaustion on embedded targets.
 *
 * Thread safety: SessionCache is NOT thread-safe.  Callers must serialize
 * access from a single thread or use an external mutex.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/session/session.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <cstddef>
#include <optional>
#include <unordered_map>
#include <vector>
#include <memory>

namespace uav_pqc::session {

/**
 * @brief A single cached session entry.
 *
 * The Session is moved into the cache after handshake completion and
 * moved back out on successful resumption.
 */
struct CacheEntry {
    Session    session;        ///< The full session state
    Timestamp  cached_at_ms;   ///< Monotonic timestamp when cached
    Timestamp  ttl_ms;         ///< Duration (ms) the entry remains valid
};

/**
 * @brief Bounded session resumption cache.
 */
class SessionCache {
public:
    static constexpr std::size_t kDefaultMaxEntries = 32;
    static constexpr Timestamp   kDefaultTtlMs      = 60000; // 60 seconds

    explicit SessionCache(std::size_t max_entries = kDefaultMaxEntries,
                          Timestamp   default_ttl_ms = kDefaultTtlMs,
                          std::shared_ptr<platform::IClock> clock = nullptr);

    ~SessionCache() = default;
    SessionCache(const SessionCache&)            = delete;
    SessionCache& operator=(const SessionCache&) = delete;
    SessionCache(SessionCache&&) noexcept        = default;
    SessionCache& operator=(SessionCache&&) noexcept = default;

    // ── Store / retrieve ──────────────────────────────────────────────────────

    /**
     * @brief Store a session in the cache.
     *
     * If the cache is full, the oldest expired entry is evicted.  If no
     * expired entry exists, the least-recently-used entry is replaced.
     *
     * @param session     Session to cache (moved in).
     * @param now_ms      Current monotonic time.
     * @param ttl_ms      Override TTL; zero uses the default.
     * @return            Ok, or ErrorCode::AllocationFailed if severely constrained.
     */
    [[nodiscard]] VoidResult store(Session&& session, Timestamp now_ms = 0, Timestamp ttl_ms = 0);

    /**
     * @brief Attempt to retrieve a cached session for resumption.
     *
     * Validates that the session has not expired and the peer NodeId matches.
     * On success, the entry is removed from the cache (consumed).
     *
     * @param session_id   SessionId from the resume request.
     * @param peer_node_id Expected NodeId (prevents session hijacking).
     * @param now_ms       Current monotonic time.
     * @return             Moved-out Session, or ErrorCode::SessionNotFound /
     *                     ErrorCode::SessionExpired.
     */
    [[nodiscard]] Result<Session> retrieve(const SessionId& session_id,
                                           const NodeId&    peer_node_id,
                                           Timestamp        now_ms = 0);

    /**
     * @brief Remove all expired entries from the cache.
     *
     * Should be called periodically (e.g. every 10 seconds) to release memory.
     * @return Number of entries evicted.
     */
    std::size_t prune(Timestamp now_ms = 0);

    // ── Metadata ──────────────────────────────────────────────────────────────

    [[nodiscard]] std::size_t size()       const noexcept { return entries_.size(); }
    [[nodiscard]] std::size_t max_entries() const noexcept { return max_entries_; }
    [[nodiscard]] bool        empty()      const noexcept { return entries_.empty(); }
    [[nodiscard]] bool        full()       const noexcept { return entries_.size() >= max_entries_; }

private:
    struct SessionIdHash {
        std::size_t operator()(const SessionId& id) const noexcept;
    };

    std::unordered_map<SessionId, CacheEntry, SessionIdHash> entries_;
    std::size_t max_entries_;
    Timestamp   default_ttl_ms_;
    std::shared_ptr<platform::IClock> clock_;
};

} // namespace uav_pqc::session
