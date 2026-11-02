// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file secure_comm.hpp
 * @brief Secure communication layer for protecting UAV application message types.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/session/session.hpp"
#include "uav_pqc/transport/fragment.hpp"

#include <cstdint>
#include <memory>
#include <vector>
#include <optional>

namespace uav_pqc::session {

/**
 * @brief Application message categories that require cryptographic protection.
 */
enum class AppCategory : std::uint8_t {
    Telemetry      = 0x01, ///< Real-time flight telemetry (confidentiality & integrity)
    Commands       = 0x02, ///< Critical control commands (strict anti-replay & integrity)
    Video          = 0x03, ///< Video stream payloads (high bandwidth, fragmentation)
    Payload        = 0x04, ///< Mission-specific sensor payloads
    Firmware       = 0x05, ///< Signed firmware updates (large binary fragments)
    MissionUpdates = 0x06  ///< Swarm mission parameter updates
};

/**
 * @brief Cleartext application message with its category tag.
 */
struct AppMessage {
    AppCategory category;
    Bytes       payload;
};

/**
 * @brief Coordinates data-plane security and fragmentation/reassembly for active links.
 */
class SecureCommLayer {
public:
    /**
     * @brief Construct secure communication layer associated with a session.
     *
     * @param session The active secure session.
     * @param mtu     MTU limit of the transport medium (used for fragmentation).
     */
    explicit SecureCommLayer(std::shared_ptr<session::Session> session, std::size_t mtu = 500);
    ~SecureCommLayer() = default;

    SecureCommLayer(const SecureCommLayer&) = delete;
    SecureCommLayer& operator=(const SecureCommLayer&) = delete;
    SecureCommLayer(SecureCommLayer&&) noexcept = default;
    SecureCommLayer& operator=(SecureCommLayer&&) noexcept = default;

    /**
     * @brief Protects and fragments an outbound application message.
     *
     * The message type category is prepended to the cleartext payload to prevent
     * traffic analysis, then encrypted using the session's AEAD.
     * The resulting ciphertext is fragmented into transport slices fitting the MTU.
     *
     * @param msg       Cleartext application message.
     * @param stream_id Unique ID for tracking this fragmented stream.
     * @param aad       Optional additional authenticated data.
     * @return          List of ready-to-transmit packet fragments.
     */
    [[nodiscard]] Result<std::vector<transport::Fragment>> protect_and_fragment(
        const AppMessage& msg,
        transport::StreamId stream_id,
        ByteSpan aad = {});

    /**
     * @brief Processes an inbound fragment, attempting reassembly and decryption.
     *
     * Feeds the fragment to the reassembly buffer. When all fragments are received,
     * it decrypts the ciphertext, checks sequence numbers and tags, and parses
     * the decrypted payload into the structured AppMessage.
     *
     * @param frag      Received transport fragment.
     * @param now_ms    Current monotonic timestamp in milliseconds.
     * @param aad       Optional additional authenticated data.
     * @return          AppMessage if reassembly and decryption succeeded,
     *                  std::nullopt if still waiting for fragments,
     *                  or an Error on verification or reassembly failure.
     */
    [[nodiscard]] Result<std::optional<AppMessage>> process_incoming_fragment(
        const transport::Fragment& frag,
        Timestamp now_ms,
        ByteSpan aad = {});

private:
    std::shared_ptr<session::Session> session_;
    std::size_t                       mtu_;
    transport::FragmentReassembler    reassembler_;
};

} // namespace uav_pqc::session
