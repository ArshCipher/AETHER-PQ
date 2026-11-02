// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file message.hpp
 * @brief Protocol wire-message types for the UAV-PQC handshake.
 *
 * All messages are serialised as TLV (Type-Length-Value) byte sequences.
 * Structured types here correspond 1-to-1 with the protocol messages in the
 * architecture specification and the Tamarin model.
 *
 * Message IDs are fixed constants — do not renumber.  They appear in:
 *   - On-wire framing
 *   - Tamarin message terms
 *   - Protocol documentation
 */

#include "uav_pqc/common/types.hpp"
#include "uav_pqc/protocol/mode.hpp"
#include "uav_pqc/protocol/suite.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace uav_pqc::protocol {

// ─────────────────────────────────────────────────────────────────────────────
// Message type codes (wire encoding)
// ─────────────────────────────────────────────────────────────────────────────

enum class MessageType : std::uint8_t {
    // Registration messages
    RegisterReq         = 0x01, ///< UAV → CA/GCS: Registration request
    RegisterAck         = 0x02, ///< CA/GCS → UAV: Registration confirmation + Cert
    RegisterReject      = 0x03, ///< CA/GCS → UAV: Registration rejection
    AuthReq             = 0x04, ///< UAV → GCS: Auth request + KEM pk
    AuthChallenge       = 0x05, ///< GCS → UAV: Challenge + GCS cert
    AuthResponse        = 0x06, ///< UAV → GCS: Response signature
    AuthSuccess         = 0x07, ///< GCS → UAV: Auth success + KEM ciphertext
    AuthFail            = 0x08, ///< Either: Fail notification

    // Handshake messages
    ClientHello         = 0x10, ///< UAV → GCS: mode proposal + KEMpk + ephemeral
    ServerHello         = 0x11, ///< GCS → UAV: mode confirmation + KEM ciphertext
    ClientAuth          = 0x12, ///< UAV → GCS: certificate + DSA signature
    ServerAuth          = 0x13, ///< GCS → UAV: certificate + DSA signature
    HandshakeFinished   = 0x14, ///< Either direction: verify transcript hash
    SessionResumeReq    = 0x15, ///< UAV → GCS: request session resumption
    SessionResumeResp   = 0x16, ///< GCS → UAV: accept/reject resumption

    // Group key management (TreeKEM)
    GroupKeyUpdate      = 0x20, ///< GCS → Swarm: encrypted group key update
    GroupMemberAdd      = 0x21, ///< GCS → Swarm: new member joined
    GroupMemberRemove   = 0x22, ///< GCS → Swarm: member removed/revoked

    // Policy / profile  (live session updates — GCS-initiated, ACPE-driven)
    ProfileUpdate       = 0x30, ///< GCS → UAV: ACPE-driven profile change
    ProfileAck          = 0x31, ///< UAV → GCS: acknowledgement

    // Mode & Profile Negotiation (initial session setup, 3-way each)
    ModeReq             = 0x50, ///< Initiator → Responder: offered modes + nonce + ML-DSA sig
    ModeResp            = 0x51, ///< Responder → Initiator: selected mode + nonce echo + ML-DSA sig
    ModeConfirm         = 0x52, ///< Initiator → Responder: confirmed mode + transcript hash + ML-DSA sig
    ProfileReq          = 0x53, ///< Initiator → Responder: proposed CipherSuite + nonce + ML-DSA sig
    ProfileResp         = 0x54, ///< Responder → Initiator: accepted/adjusted suite + nonce echo + ML-DSA sig
    ProfileConfirm      = 0x55, ///< Initiator → Responder: final ack + transcript hash + ML-DSA sig

    // Data-plane (used by transport layer framing)
    EncryptedPayload    = 0x40, ///< Session-encrypted unicast payload
    Fragment            = 0x41, ///< Application-layer fragment
    FragmentAck         = 0x42, ///< Selective retransmission ACK

    // D2D Ephemeral Session Coordination & Direct Payload
    D2DSessionReq       = 0x60, ///< UAV-A → GCS: D2D Session Request
    D2DSessionResp      = 0x61, ///< GCS → UAV-A / UAV-B: D2D Key Distribution
    D2DSessionReject    = 0x62, ///< GCS → UAV-A: D2D Session Rejection
    D2DSessionTerm      = 0x63, ///< UAV / GCS → Peer: Explicit D2D Termination
    D2DData             = 0x64, ///< Peer ↔ Peer: Direct Encrypted D2D Payload
    D2DDirectHello      = 0x65, ///< Direct UAV-A → UAV-B PQC Key Exchange Offer
    D2DDirectResp       = 0x66, ///< Direct UAV-B → UAV-A PQC Key Exchange Response
    D2DDirectConfirm    = 0x67, ///< Direct UAV-A → UAV-B Final PQC Session Ack

    // Control
    Alert               = 0xF0, ///< Error / warning notification
    Shutdown            = 0xFF, ///< Clean session termination
};

enum class ProtocolID : std::uint8_t {
    HANDSHAKE = 1,
    TELEMETRY = 2,
    COMMAND   = 3,
    TREEKEM   = 4,
    HEARTBEAT = 5,
    D2D       = 6,
    VIDEO     = 7
};

struct UniversalHeader {
    static constexpr std::uint32_t kMagic = 0x55505143; // 'UPQC'
    static constexpr std::size_t kWireSize = 4 + 1 + 1 + 1 + 4 + 16 + 4; // = 31 bytes

    std::uint32_t   magic = kMagic;
    std::uint8_t    version = 0x01;
    ProtocolID      protocol_id = ProtocolID::HANDSHAKE;
    std::uint8_t    message_type = 0;
    std::uint32_t   payload_length = 0;
    SessionId       session_id{};
    std::uint32_t   flags = 0;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<UniversalHeader> deserialise(ByteSpan data);
};

[[nodiscard]] Bytes wrap_packet(ProtocolID id, ByteSpan payload, std::uint8_t msg_type = 0, const SessionId& session_id = {}, std::uint32_t flags = 0);

// ─────────────────────────────────────────────────────────────────────────────
// Common message header (prepended to every wire message)
// ─────────────────────────────────────────────────────────────────────────────

struct MessageHeader {
    MessageType     type;                     ///< Message type code
    std::uint8_t    version = 0x01;           ///< Protocol version (0x01 = this spec)
    std::uint16_t   length  = 0;              ///< Length of the body following this header
    SessionId       session_id{};             ///< Identifies the session (or zeros for pre-session)
    SequenceNumber  sequence_number = 0;      ///< Monotonic per-session counter (anti-replay)

    static constexpr std::size_t kWireSize = 1 + 1 + 2 + 16 + 8; // = 28 bytes

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<MessageHeader> deserialise(ByteSpan data);
};

// ─────────────────────────────────────────────────────────────────────────────
// Handshake message structures
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief ClientHello — initiating message from UAV to GCS.
 *
 * Carries:
 *  - The list of operating modes the UAV supports (priority order)
 *  - The UAV's ephemeral public key for each supported KEM
 *  - A random nonce for transcript binding and anti-replay
 *  - The UAV's NodeId (hash of its long-term public key)
 */
struct ClientHello {
    NodeId       node_id;                         ///< UAV's node identifier
    Bytes        client_random;                   ///< 32 random bytes
    std::vector<OperatingMode> supported_modes;   ///< Priority-ordered supported modes
    Bytes        kem_public_key;                  ///< Ephemeral KEM public key (highest mode)
    Bytes        x25519_public_key;               ///< Ephemeral X25519 public key (if hybrid capable)
    std::uint32_t protocol_version = 0x00010000; ///< Major.Minor.Patch in BCD

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<ClientHello> deserialise(ByteSpan data);
};

/**
 * @brief ServerHello — GCS response confirming mode and returning KEM ciphertext.
 */
struct ServerHello {
    NodeId          node_id;          ///< GCS node identifier
    Bytes           server_random;    ///< 32 random bytes
    OperatingMode   selected_mode;    ///< Confirmed operating mode
    CipherSuite     cipher_suite;     ///< Complete algorithm selection
    Bytes           kem_ciphertext;   ///< ML-KEM ciphertext (or hybrid ciphertext)
    Bytes           x25519_public_key;///< GCS ephemeral X25519 public key (Hybrid only)

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<ServerHello> deserialise(ByteSpan data);
};

/**
 * @brief Authentication message (ClientAuth / ServerAuth).
 *
 * Carries the sender's certificate chain and a transcript signature.
 * In Hybrid mode both ml_dsa_signature and ecdsa_signature are present.
 */
struct AuthMessage {
    Bytes certificate_chain;           ///< DER-encoded certificate chain (leaf-first)
    Bytes ml_dsa_signature;            ///< ML-DSA signature over transcript hash (empty in Classical/Transition)
    Bytes ecdsa_signature;             ///< ECDSA-P256 signature over transcript hash (empty in PQC-Only)

    [[nodiscard]] bool has_pqc_signature()      const noexcept { return !ml_dsa_signature.empty(); }
    [[nodiscard]] bool has_classical_signature() const noexcept { return !ecdsa_signature.empty(); }

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<AuthMessage> deserialise(ByteSpan data);
};

/**
 * @brief HandshakeFinished — transcript integrity verification.
 *
 * Contains HMAC-SHA256 of the full handshake transcript under the
 * derived finished_key (prevents downgrade on the MAC layer).
 */
struct HandshakeFinished {
    std::array<std::byte, 32> verify_data{}; ///< HMAC of transcript hash

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<HandshakeFinished> deserialise(ByteSpan data);
};

// ─────────────────────────────────────────────────────────────────────────────
// Alert message
// ─────────────────────────────────────────────────────────────────────────────

enum class AlertLevel : std::uint8_t {
    Warning  = 0x01,
    Fatal    = 0x02,
};

enum class AlertCode : std::uint8_t {
    UnexpectedMessage  = 0x01,
    BadCertificate     = 0x02,
    UnsupportedMode    = 0x03,
    HandshakeFailure   = 0x04,
    DecryptionFailed   = 0x05,
    PolicyViolation    = 0x06,
    InternalError      = 0xFF,
};

struct AlertMessage {
    AlertLevel level;
    AlertCode  code;
    std::string description; ///< Human-readable (not sent in PQC-Only hardened mode)

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<AlertMessage> deserialise(ByteSpan data);
};

} // namespace uav_pqc::protocol
