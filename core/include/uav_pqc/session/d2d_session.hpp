// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file d2d_session.hpp
 * @brief Ephemeral D2D Session data structures.
 */

#include "uav_pqc/common/types.hpp"

#include <cstdint>
#include <string>

namespace uav_pqc::session {

enum class D2DSessionState : std::uint8_t {
    Active     = 1,
    Expired    = 2,
    Terminated = 3
};

/**
 * @brief Ephemeral D2D Session holding peer address, 256-bit AES key, and expiration metadata.
 */
struct D2DSession {
    SessionId       session_id{};
    NodeId          local_node_id{};
    NodeId          peer_node_id{};
    std::string     peer_ip;
    std::uint16_t   peer_port = 0;
    SecureBytes     session_key; // 32-byte (256-bit) ephemeral key
    Timestamp       created_at = 0;
    Timestamp       expires_at = 0;
    Timestamp       last_active_at = 0;
    std::uint32_t   lifetime_seconds = 300;
    std::uint32_t   inactivity_timeout_seconds = 60;
    SequenceNumber  tx_seq = 0;
    SequenceNumber  rx_seq = 0;
    D2DSessionState state = D2DSessionState::Active;
    bool            is_initiator = false;

    D2DSession() = default;
    D2DSession(D2DSession&&) noexcept = default;
    D2DSession& operator=(D2DSession&&) noexcept = default;
    D2DSession(const D2DSession&) = delete;
    D2DSession& operator=(const D2DSession&) = delete;

    [[nodiscard]] D2DSession clone() const {
        D2DSession copy;
        copy.session_id = session_id;
        copy.local_node_id = local_node_id;
        copy.peer_node_id = peer_node_id;
        copy.peer_ip = peer_ip;
        copy.peer_port = peer_port;
        if (!session_key.empty()) {
            copy.session_key = SecureBytes(Bytes(session_key.bytes().begin(), session_key.bytes().end()));
        }
        copy.created_at = created_at;
        copy.expires_at = expires_at;
        copy.last_active_at = last_active_at;
        copy.lifetime_seconds = lifetime_seconds;
        copy.inactivity_timeout_seconds = inactivity_timeout_seconds;
        copy.tx_seq = tx_seq;
        copy.rx_seq = rx_seq;
        copy.state = state;
        copy.is_initiator = is_initiator;
        return copy;
    }

    [[nodiscard]] bool is_expired(Timestamp now) const noexcept {
        if (state != D2DSessionState::Active) return true;
        if (expires_at > 0 && now >= expires_at) return true;
        if (inactivity_timeout_seconds > 0 && last_active_at > 0) {
            if (now >= last_active_at + (static_cast<std::uint64_t>(inactivity_timeout_seconds) * 1000)) {
                return true;
            }
        }
        return false;
    }

    void touch(Timestamp now) noexcept {
        last_active_at = now;
    }
};

struct SessionIdHash {
    std::size_t operator()(const SessionId& id) const noexcept {
        std::size_t hash = 0;
        for (auto b : id) {
            hash = (hash * 31) + static_cast<std::size_t>(b);
        }
        return hash;
    }
};

/**
 * @brief Runtime statistics for D2D Session Manager.
 */
struct D2DStatistics {
    std::size_t active_sessions = 0;
    std::size_t total_sessions_created = 0;
    std::size_t total_sessions_expired = 0;
    std::size_t total_sessions_terminated = 0;
    std::uint64_t total_bytes_sent = 0;
    std::uint64_t total_bytes_received = 0;
    std::uint64_t total_packets_sent = 0;
    std::uint64_t total_packets_received = 0;
};

} // namespace uav_pqc::session
