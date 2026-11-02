// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file d2d_messages.hpp
 * @brief Wire serialisation for D2D Ephemeral Session establishment and management payloads.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/protocol/message.hpp"

#include <cstdint>
#include <string>

namespace uav_pqc::protocol {

/**
 * @brief Rejection reason codes for D2DSessionReject payload.
 */
enum class D2DRejectReason : std::uint8_t {
    PolicyDenied    = 0x01,
    TargetOffline   = 0x02,
    CertRevoked     = 0x03,
    LimitExceeded   = 0x04,
    InvalidParams   = 0x05,
    InternalError   = 0xFF
};

/**
 * @brief D2D Session Request payload (UAV-A → GCS).
 */
struct D2DSessionReqPayload {
    NodeId        initiator_node_id{};
    NodeId        target_node_id{};
    std::uint32_t requested_lifetime_seconds = 300;
    std::string   traffic_reason;

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<D2DSessionReqPayload> deserialize(ByteSpan bytes);
};

/**
 * @brief D2D Session Response / Key Distribution payload (GCS → UAV-A & UAV-B).
 */
struct D2DSessionRespPayload {
    SessionId     session_id{};
    NodeId        initiator_node_id{};
    NodeId        target_node_id{};
    std::string   target_ip;
    std::uint16_t target_port = 0;
    SecureBytes   session_key; // 32-byte (256-bit) ephemeral AES-256 key
    std::uint32_t lifetime_seconds = 300;
    std::uint32_t inactivity_timeout_seconds = 60;

    D2DSessionRespPayload() = default;
    D2DSessionRespPayload(D2DSessionRespPayload&&) noexcept = default;
    D2DSessionRespPayload& operator=(D2DSessionRespPayload&&) noexcept = default;
    D2DSessionRespPayload(const D2DSessionRespPayload&) = delete;
    D2DSessionRespPayload& operator=(const D2DSessionRespPayload&) = delete;

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<D2DSessionRespPayload> deserialize(ByteSpan bytes);
};

/**
 * @brief D2D Session Rejection payload (GCS → UAV-A).
 */
struct D2DSessionRejectPayload {
    NodeId          initiator_node_id{};
    NodeId          target_node_id{};
    D2DRejectReason reason_code = D2DRejectReason::PolicyDenied;
    std::string     reason_msg;

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<D2DSessionRejectPayload> deserialize(ByteSpan bytes);
};

/**
 * @brief D2D Session Termination payload (UAV / GCS → Peer).
 */
struct D2DSessionTermPayload {
    SessionId     session_id{};
    NodeId        sender_node_id{};
    std::uint8_t  term_reason = 1; // 1=Expired, 2=Inactivity, 3=Explicit, 4=Error

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<D2DSessionTermPayload> deserialize(ByteSpan bytes);
};

} // namespace uav_pqc::protocol
