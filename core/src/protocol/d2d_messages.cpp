// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/protocol/d2d_messages.hpp"
#include "uav_pqc/common/strong_types.hpp"

#include <cstring>
#include <stdexcept>

namespace uav_pqc::protocol {

// Helper big-endian functions
static inline void write_u16_be(std::uint16_t val, Bytes& out) {
    out.push_back(static_cast<std::byte>((val >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(val & 0xFF));
}

static inline void write_u32_be(std::uint32_t val, Bytes& out) {
    out.push_back(static_cast<std::byte>((val >> 24) & 0xFF));
    out.push_back(static_cast<std::byte>((val >> 16) & 0xFF));
    out.push_back(static_cast<std::byte>((val >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(val & 0xFF));
}

static inline std::uint16_t read_u16_be(ByteSpan span) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(span[0]) << 8) |
         static_cast<std::uint16_t>(span[1]));
}

static inline std::uint32_t read_u32_be(ByteSpan span) {
    return (static_cast<std::uint32_t>(span[0]) << 24) |
           (static_cast<std::uint32_t>(span[1]) << 16) |
           (static_cast<std::uint32_t>(span[2]) << 8)  |
            static_cast<std::uint32_t>(span[3]);
}

// ─────────────────────────────────────────────────────────────────────────────
// D2DSessionReqPayload
// ─────────────────────────────────────────────────────────────────────────────

Bytes D2DSessionReqPayload::serialize() const {
    Bytes out;
    out.reserve(32 + 32 + 4 + 2 + traffic_reason.size());

    out.insert(out.end(), initiator_node_id.begin(), initiator_node_id.end());
    out.insert(out.end(), target_node_id.begin(), target_node_id.end());
    write_u32_be(requested_lifetime_seconds, out);

    auto r_len = static_cast<std::uint16_t>(traffic_reason.size());
    write_u16_be(r_len, out);
    for (char c : traffic_reason) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

Result<D2DSessionReqPayload> D2DSessionReqPayload::deserialize(ByteSpan bytes) {
    if (bytes.size() < 32 + 32 + 4 + 2) {
        return ErrorCode::InvalidArgument;
    }
    D2DSessionReqPayload payload;
    std::memcpy(payload.initiator_node_id.data(), bytes.data(), 32);
    std::memcpy(payload.target_node_id.data(), bytes.data() + 32, 32);
    payload.requested_lifetime_seconds = read_u32_be(bytes.subspan(64, 4));

    std::uint16_t r_len = read_u16_be(bytes.subspan(68, 2));
    if (bytes.size() < 70 + r_len) {
        return ErrorCode::InvalidArgument;
    }
    if (r_len > 0) {
        payload.traffic_reason.assign(
            reinterpret_cast<const char*>(bytes.data() + 70), r_len);
    }
    return payload;
}

// ─────────────────────────────────────────────────────────────────────────────
// D2DSessionRespPayload
// ─────────────────────────────────────────────────────────────────────────────

Bytes D2DSessionRespPayload::serialize() const {
    Bytes out;
    out.reserve(16 + 32 + 32 + 2 + target_ip.size() + 2 + 32 + 4 + 4);

    out.insert(out.end(), session_id.begin(), session_id.end());
    out.insert(out.end(), initiator_node_id.begin(), initiator_node_id.end());
    out.insert(out.end(), target_node_id.begin(), target_node_id.end());

    auto ip_len = static_cast<std::uint16_t>(target_ip.size());
    write_u16_be(ip_len, out);
    for (char c : target_ip) {
        out.push_back(static_cast<std::byte>(c));
    }

    write_u16_be(target_port, out);

    // Key must be exactly 32 bytes (AES-256)
    if (session_key.size() == 32) {
        out.insert(out.end(), session_key.data(), session_key.data() + 32);
    } else {
        out.insert(out.end(), 32, std::byte{0});
    }

    write_u32_be(lifetime_seconds, out);
    write_u32_be(inactivity_timeout_seconds, out);
    return out;
}

Result<D2DSessionRespPayload> D2DSessionRespPayload::deserialize(ByteSpan bytes) {
    // 16 + 32 + 32 + 2 = 82 min header before IP
    if (bytes.size() < 82) {
        return ErrorCode::InvalidArgument;
    }
    D2DSessionRespPayload payload;
    std::memcpy(payload.session_id.data(), bytes.data(), 16);
    std::memcpy(payload.initiator_node_id.data(), bytes.data() + 16, 32);
    std::memcpy(payload.target_node_id.data(), bytes.data() + 48, 32);

    std::uint16_t ip_len = read_u16_be(bytes.subspan(80, 2));
    std::size_t pos = 82;
    if (bytes.size() < pos + ip_len + 2 + 32 + 4 + 4) {
        return ErrorCode::InvalidArgument;
    }

    if (ip_len > 0) {
        payload.target_ip.assign(
            reinterpret_cast<const char*>(bytes.data() + pos), ip_len);
    }
    pos += ip_len;

    payload.target_port = read_u16_be(bytes.subspan(pos, 2));
    pos += 2;

    payload.session_key.resize(32);
    std::memcpy(payload.session_key.data(), bytes.data() + pos, 32);
    pos += 32;

    payload.lifetime_seconds = read_u32_be(bytes.subspan(pos, 4));
    pos += 4;

    payload.inactivity_timeout_seconds = read_u32_be(bytes.subspan(pos, 4));
    return payload;
}

// ─────────────────────────────────────────────────────────────────────────────
// D2DSessionRejectPayload
// ─────────────────────────────────────────────────────────────────────────────

Bytes D2DSessionRejectPayload::serialize() const {
    Bytes out;
    out.reserve(32 + 32 + 1 + 2 + reason_msg.size());

    out.insert(out.end(), initiator_node_id.begin(), initiator_node_id.end());
    out.insert(out.end(), target_node_id.begin(), target_node_id.end());
    out.push_back(static_cast<std::byte>(reason_code));

    auto m_len = static_cast<std::uint16_t>(reason_msg.size());
    write_u16_be(m_len, out);
    for (char c : reason_msg) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

Result<D2DSessionRejectPayload> D2DSessionRejectPayload::deserialize(ByteSpan bytes) {
    if (bytes.size() < 32 + 32 + 1 + 2) {
        return ErrorCode::InvalidArgument;
    }
    D2DSessionRejectPayload payload;
    std::memcpy(payload.initiator_node_id.data(), bytes.data(), 32);
    std::memcpy(payload.target_node_id.data(), bytes.data() + 32, 32);
    payload.reason_code = static_cast<D2DRejectReason>(bytes[64]);

    std::uint16_t m_len = read_u16_be(bytes.subspan(65, 2));
    if (bytes.size() < 67 + m_len) {
        return ErrorCode::InvalidArgument;
    }
    if (m_len > 0) {
        payload.reason_msg.assign(
            reinterpret_cast<const char*>(bytes.data() + 67), m_len);
    }
    return payload;
}

// ─────────────────────────────────────────────────────────────────────────────
// D2DSessionTermPayload
// ─────────────────────────────────────────────────────────────────────────────

Bytes D2DSessionTermPayload::serialize() const {
    Bytes out;
    out.reserve(16 + 32 + 1);

    out.insert(out.end(), session_id.begin(), session_id.end());
    out.insert(out.end(), sender_node_id.begin(), sender_node_id.end());
    out.push_back(static_cast<std::byte>(term_reason));
    return out;
}

Result<D2DSessionTermPayload> D2DSessionTermPayload::deserialize(ByteSpan bytes) {
    if (bytes.size() < 16 + 32 + 1) {
        return ErrorCode::InvalidArgument;
    }
    D2DSessionTermPayload payload;
    std::memcpy(payload.session_id.data(), bytes.data(), 16);
    std::memcpy(payload.sender_node_id.data(), bytes.data() + 16, 32);
    payload.term_reason = static_cast<std::uint8_t>(bytes[48]);
    return payload;
}

} // namespace uav_pqc::protocol
