// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file d2d_manager.hpp
 * @brief Thread-safe manager for Ephemeral D2D Sessions with automatic key zeroization and anti-replay protection.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/session/d2d_session.hpp"

#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace uav_pqc::session {

class D2DSessionManager {
public:
    D2DSessionManager() = default;
    ~D2DSessionManager() { clear_all(); }

    D2DSessionManager(const D2DSessionManager&) = delete;
    D2DSessionManager& operator=(const D2DSessionManager&) = delete;

    /**
     * @brief Register or update a D2D session.
     */
    Result<SessionId> add_session(D2DSession session);

    /**
     * @brief Lookup session by SessionId.
     */
    [[nodiscard]] std::optional<D2DSession> get_session(const SessionId& sid);

    /**
     * @brief Lookup active session by peer NodeId.
     */
    [[nodiscard]] std::optional<D2DSession> find_session_by_peer(const NodeId& peer_id);

    /**
     * @brief Terminate and erase a session explicitly.
     */
    bool terminate_session(const SessionId& sid);

    /**
     * @brief Periodically clean up expired or timed-out sessions.
     * @return Number of sessions pruned.
     */
    std::size_t cleanup_expired_sessions(Timestamp current_time);

    /**
     * @brief Clear all sessions and zeroize keys.
     */
    void clear_all();

    /**
     * @brief Encrypt a direct D2D application payload using the session's AES-256-GCM key.
     */
    Result<Bytes> encrypt_payload(const SessionId& sid, ByteSpan plaintext, Timestamp now);

    /**
     * @brief Decrypt a direct D2D application payload using the session's AES-256-GCM key.
     */
    Result<Bytes> decrypt_payload(const SessionId& sid, ByteSpan ciphertext, Timestamp now);

    /**
     * @brief Retrieve runtime statistics.
     */
    [[nodiscard]] D2DStatistics get_statistics() const;

    /**
     * @brief Retrieve the exact size of a single D2DSession object including dynamic allocations.
     */
    [[nodiscard]] static std::size_t get_session_object_size(const D2DSession& session) noexcept;

    /**
     * @brief Get the active session memory representing the dynamic size of all sessions currently tracked.
     */
    [[nodiscard]] std::size_t get_active_session_memory() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<SessionId, D2DSession, SessionIdHash> sessions_;
    D2DStatistics stats_;
};

} // namespace uav_pqc::session
