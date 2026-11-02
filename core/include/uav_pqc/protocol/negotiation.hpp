// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file negotiation.hpp
 * @brief Operating Mode and Cryptographic Profile Negotiation sub-protocol.
 *
 * This sub-protocol runs after mutual authentication and before any session
 * data flows.  It establishes the agreed OperatingMode and CipherSuite via two
 * independent 3-way handshakes, each protected by ML-DSA signatures to prevent
 * downgrade attacks.
 *
 * Protocol flow (both handshakes are sequential, mode first):
 *
 *   Initiator (UAV)                   Responder (GCS)
 *       │                                   │
 *       │── ModeReq ──────────────────────▶ │  offered modes + nonce + ML-DSA sig
 *       │◀── ModeResp ──────────────────── │  selected mode + nonces + ML-DSA sig
 *       │── ModeConfirm ─────────────────▶ │  confirmed mode + transcript hash + ML-DSA sig
 *       │                                   │
 *       │── ProfileReq ──────────────────▶ │  proposed CipherSuite + nonce + ML-DSA sig
 *       │◀── ProfileResp ────────────────── │  accepted/adjusted suite + nonces + ML-DSA sig
 *       │── ProfileConfirm ───────────────▶ │  final ack + transcript hash + ML-DSA sig
 *
 * Downgrade prevention:
 *   1. Every message is ML-DSA signed; forged messages are cryptographically rejected.
 *   2. Mode floor: the responder never selects a mode weaker than its ACPE policy
 *      floor; the initiator rejects any response below its own floor.
 *   3. Suite monotonicity: the initiator rejects a suite whose mode is weaker than
 *      the negotiated mode; ACPE::validate_peer_suite() is called on every resp.
 *   4. Transcript hash binding: ModeConfirm/ProfileConfirm bind all preceding
 *      messages via SHA-256; a replayed or mutated earlier message breaks the hash.
 *   5. Nonce anti-replay: each REQ carries a fresh 32-byte nonce; the RESP echoes
 *      it; a mismatched echo terminates the session.
 *
 * All operations return Result<T> / VoidResult — no exceptions, no global state.
 *
 * Tamarin note:
 *   Each message in this sub-protocol maps directly to a Tamarin message term.
 *   The transcript hash in the CONFIRM messages provides the linking term needed
 *   to prove agreement under the session-key-agreement security property.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/protocol/message.hpp"
#include "uav_pqc/protocol/mode.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace uav_pqc::crypto { class ICryptoProvider; }

namespace uav_pqc::protocol {

// ─────────────────────────────────────────────────────────────────────────────
// State machine observable states
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Observable states of the negotiation state machines.
 *
 * Both the Initiator and the Responder machines use this enum.
 * The progression is always monotonic; once Failed is reached no further
 * transitions are possible and the machine must be discarded.
 */
enum class NegotiationState : std::uint8_t {
    Idle               = 0, ///< Not yet started
    WaitModeResp       = 1, ///< Initiator: sent ModeReq, awaiting ModeResp
    WaitModeConfirm    = 2, ///< Responder: sent ModeResp, awaiting ModeConfirm
    WaitProfileReq     = 3, ///< Responder: mode confirmed, awaiting ProfileReq
    WaitProfileResp    = 4, ///< Initiator: sent ProfileReq, awaiting ProfileResp
    WaitProfileConfirm = 5, ///< Responder: sent ProfileResp, awaiting ProfileConfirm
    Complete           = 6, ///< Both sides have confirmed; result is available
    Failed             = 7, ///< Protocol error; machine must be discarded
};

// ─────────────────────────────────────────────────────────────────────────────
// Wire message structures
// ─────────────────────────────────────────────────────────────────────────────

/** @brief Nonce size for negotiation messages: 32 bytes (256-bit). */
static constexpr std::size_t kNegotiationNonceSize = 32;

/** @brief Transcript hash size: SHA-256 = 32 bytes. */
static constexpr std::size_t kTranscriptHashSize = 32;

/**
 * @brief MODE_REQ — Initiator → Responder.
 *
 * Wire layout (all lengths in bytes):
 *   node_id         (32)
 *   nonce           (2-len prefix + 32 bytes)
 *   timestamp       (8)
 *   n_modes         (1)          — number of offered modes
 *   mode[0..n-1]    (1 each)    — OperatingMode values, priority order
 *   signature       (2-len prefix + ML-DSA sig bytes)
 *
 * Signed bytes = all fields except the signature field itself.
 */
struct ModeReqMsg {
    NodeId                       node_id{};
    Bytes                        nonce;           ///< 32 cryptographically-random bytes
    Timestamp                    timestamp = 0;
    std::vector<OperatingMode>   offered_modes;   ///< Priority-ordered, highest preference first
    Bytes                        signature;        ///< ML-DSA sig over get_signed_bytes()

    [[nodiscard]] Bytes           serialise() const;
    [[nodiscard]] static Result<ModeReqMsg> deserialise(ByteSpan data);
    [[nodiscard]] Bytes           get_signed_bytes() const;
};

/**
 * @brief MODE_RESP — Responder → Initiator.
 *
 * Wire layout:
 *   node_id         (32)
 *   echo_nonce      (2-len prefix + 32)   — mirrors ModeReqMsg::nonce
 *   resp_nonce      (2-len prefix + 32)   — fresh responder nonce
 *   selected_mode   (1)
 *   timestamp       (8)
 *   signature       (2-len prefix + ML-DSA sig bytes)
 */
struct ModeRespMsg {
    NodeId          node_id{};
    Bytes           echo_nonce;     ///< Echo of ModeReqMsg::nonce (anti-replay binding)
    Bytes           resp_nonce;     ///< Fresh 32-byte responder nonce
    OperatingMode   selected_mode = OperatingMode::Hybrid;
    Timestamp       timestamp = 0;
    Bytes           signature;

    [[nodiscard]] Bytes           serialise() const;
    [[nodiscard]] static Result<ModeRespMsg> deserialise(ByteSpan data);
    [[nodiscard]] Bytes           get_signed_bytes() const;
};

/**
 * @brief MODE_CONFIRM — Initiator → Responder.
 *
 * Wire layout:
 *   confirmed_mode      (1)
 *   transcript_hash     (32)   — SHA-256(ModeReqMsg::serialise() || ModeRespMsg::serialise())
 *   signature           (2-len prefix + ML-DSA sig bytes)
 */
struct ModeConfirmMsg {
    OperatingMode                    confirmed_mode = OperatingMode::Hybrid;
    std::array<std::byte, kTranscriptHashSize> transcript_hash{};
    Bytes                            signature;

    [[nodiscard]] Bytes              serialise() const;
    [[nodiscard]] static Result<ModeConfirmMsg> deserialise(ByteSpan data);
    [[nodiscard]] Bytes              get_signed_bytes() const;
};

/**
 * @brief PROFILE_REQ — Initiator → Responder.
 *
 * Wire layout:
 *   node_id         (32)
 *   nonce           (2-len prefix + 32)
 *   timestamp       (8)
 *   kem_level       (1)
 *   dsa_level       (1)
 *   aead_algorithm  (1)
 *   hkdf_hash       (1)
 *   signature       (2-len prefix + ML-DSA sig bytes)
 *
 * The embedded CipherSuite must be compatible with the already-confirmed mode.
 */
struct ProfileReqMsg {
    NodeId           node_id{};
    Bytes            nonce;
    Timestamp        timestamp = 0;
    crypto::MlKem::Level kem_level   = crypto::MlKem::Level::Kem768;
    crypto::MlDsa::Level dsa_level   = crypto::MlDsa::Level::Dsa65;
    AeadAlgorithm    aead_algorithm  = AeadAlgorithm::AesGcm256;
    crypto::HkdfHash hkdf_hash       = crypto::HkdfHash::Sha256;
    Bytes            signature;

    [[nodiscard]] Bytes              serialise() const;
    [[nodiscard]] static Result<ProfileReqMsg> deserialise(ByteSpan data);
    [[nodiscard]] Bytes              get_signed_bytes() const;
};

/**
 * @brief PROFILE_RESP — Responder → Initiator.
 *
 * Wire layout:
 *   echo_nonce      (2-len prefix + 32)
 *   resp_nonce      (2-len prefix + 32)
 *   accepted        (1)          — 0x01 = accepted as-is; 0x00 = modified
 *   kem_level       (1)
 *   dsa_level       (1)
 *   aead_algorithm  (1)
 *   hkdf_hash       (1)
 *   timestamp       (8)
 *   signature       (2-len prefix + ML-DSA sig bytes)
 *
 * If accepted==0x00 the initiator must validate the modified suite via ACPE.
 */
struct ProfileRespMsg {
    Bytes            echo_nonce;
    Bytes            resp_nonce;
    bool             accepted = true;
    crypto::MlKem::Level kem_level   = crypto::MlKem::Level::Kem768;
    crypto::MlDsa::Level dsa_level   = crypto::MlDsa::Level::Dsa65;
    AeadAlgorithm    aead_algorithm  = AeadAlgorithm::AesGcm256;
    crypto::HkdfHash hkdf_hash       = crypto::HkdfHash::Sha256;
    Timestamp        timestamp = 0;
    Bytes            signature;

    [[nodiscard]] Bytes              serialise() const;
    [[nodiscard]] static Result<ProfileRespMsg> deserialise(ByteSpan data);
    [[nodiscard]] Bytes              get_signed_bytes() const;
};

/**
 * @brief PROFILE_CONFIRM — Initiator → Responder.
 *
 * Wire layout:
 *   accepted            (1)   — 0x01 = suite accepted; 0x00 = rejected (abort)
 *   transcript_hash     (32)  — SHA-256 of all 5 preceding negotiation messages
 *   signature           (2-len prefix + ML-DSA sig bytes)
 */
struct ProfileConfirmMsg {
    bool                                      accepted = true;
    std::array<std::byte, kTranscriptHashSize> transcript_hash{};
    Bytes                                      signature;

    [[nodiscard]] Bytes              serialise() const;
    [[nodiscard]] static Result<ProfileConfirmMsg> deserialise(ByteSpan data);
    [[nodiscard]] Bytes              get_signed_bytes() const;
};

// ─────────────────────────────────────────────────────────────────────────────
// Negotiation result
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief The product of a completed negotiation.
 *
 * The negotiated_mode and negotiated_suite are the agreed-upon values that
 * BOTH sides have authenticated and confirmed.  They are handed to the session
 * layer to parameterise the secure channel.
 */
struct NegotiationResult {
    OperatingMode  negotiated_mode;
    CipherSuite    negotiated_suite;
};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Configuration supplied to both Initiator and Responder machines.
 */
struct NegotiationConfig {
    /// This node's identifier (SHA-256 of long-term public key).
    NodeId our_node_id{};

    /// Long-term ML-DSA key pair used to sign all outgoing negotiation messages.
    crypto::DsaKeyPair our_ml_dsa_key;

    /// The peer's ML-DSA public key (obtained from their certificate after auth).
    crypto::DsaPublicKey peer_ml_dsa_pub;

    /// Modes this node is willing to accept (priority order, strongest first).
    std::vector<OperatingMode> offered_modes;

    /// Minimum mode this node will accept regardless of what the peer proposes.
    /// Enforces the ACPE's policy floor on both sides.
    OperatingMode minimum_mode = OperatingMode::Transition;

    /// ML-DSA security level to use for signing negotiation messages.
    /// Standard → Dsa65; Hardened → Dsa87; Lightweight → Dsa44.
    crypto::MlDsa::Level signing_level = crypto::MlDsa::Level::Dsa65;

    /// Maximum clock skew accepted between the initiator and responder timestamps.
    /// Messages outside this window are rejected as possible replays.
    std::uint64_t max_clock_skew_ms = 300'000; // 5 minutes

    /// Crypto provider (optional; if null, DefaultCryptoProvider will be used).
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider = nullptr;
};

// ─────────────────────────────────────────────────────────────────────────────
// Abstract interfaces
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Abstract initiator (UAV side) state machine interface.
 *
 * Usage:
 *   auto init = make_negotiation_initiator(config, acpe);
 *   init->set_send_fn(channel_write_fn);
 *   init->start(now_ms);          // sends ModeReq
 *   init->feed_message(bytes);    // feed ModeResp → sends ModeConfirm
 *   init->feed_message(bytes);    // feed ProfileResp → sends ProfileConfirm
 *   // state() == NegotiationState::Complete
 *   auto result = init->result().value();
 */
class INegotiationInitiator {
public:
    using SendFn = std::function<VoidResult(Bytes wire_bytes)>;

    INegotiationInitiator()                                            = default;
    INegotiationInitiator(const INegotiationInitiator&)                = delete;
    INegotiationInitiator& operator=(const INegotiationInitiator&)     = delete;
    INegotiationInitiator(INegotiationInitiator&&) noexcept            = default;
    INegotiationInitiator& operator=(INegotiationInitiator&&) noexcept = default;
    virtual ~INegotiationInitiator()                                   = default;

    virtual void set_send_fn(SendFn fn) = 0;

    /**
     * @brief Start the negotiation; sends ModeReq immediately.
     * @param now_ms  Current wall-clock time in milliseconds.
     */
    [[nodiscard]] virtual VoidResult start(Timestamp now_ms) = 0;

    /**
     * @brief Feed an incoming wire message (with MessageHeader prepended).
     *
     * Expected sequence:
     *   - ModeResp  → validates, sends ModeConfirm, transitions to WaitProfileResp
     *   - ProfileResp → validates, sends ProfileConfirm, transitions to Complete
     */
    [[nodiscard]] virtual VoidResult feed_message(ByteSpan wire_bytes, Timestamp now_ms) = 0;

    [[nodiscard]] virtual NegotiationState state() const noexcept = 0;

    /**
     * @brief Returns the negotiation result.
     * Valid only when state() == NegotiationState::Complete.
     */
    [[nodiscard]] virtual Result<NegotiationResult> result() const = 0;
};

/**
 * @brief Abstract responder (GCS side) state machine interface.
 *
 * Usage:
 *   auto resp = make_negotiation_responder(config, acpe);
 *   resp->set_send_fn(channel_write_fn);
 *   resp->feed_message(bytes);  // ModeReq  → validates, sends ModeResp
 *   resp->feed_message(bytes);  // ModeConfirm → validates; now waits for ProfileReq
 *   resp->feed_message(bytes);  // ProfileReq → validates, sends ProfileResp
 *   resp->feed_message(bytes);  // ProfileConfirm → validates, Complete
 */
class INegotiationResponder {
public:
    using SendFn = std::function<VoidResult(Bytes wire_bytes)>;

    INegotiationResponder()                                            = default;
    INegotiationResponder(const INegotiationResponder&)                = delete;
    INegotiationResponder& operator=(const INegotiationResponder&)     = delete;
    INegotiationResponder(INegotiationResponder&&) noexcept            = default;
    INegotiationResponder& operator=(INegotiationResponder&&) noexcept = default;
    virtual ~INegotiationResponder()                                   = default;

    virtual void set_send_fn(SendFn fn) = 0;

    /**
     * @brief Feed an incoming wire message.
     *
     * Expected sequence:
     *   - ModeReq     → sends ModeResp, transitions to WaitModeConfirm
     *   - ModeConfirm → validates, transitions to WaitProfileReq
     *   - ProfileReq  → validates, sends ProfileResp, transitions to WaitProfileConfirm
     *   - ProfileConfirm → validates, transitions to Complete
     */
    [[nodiscard]] virtual VoidResult feed_message(ByteSpan wire_bytes, Timestamp now_ms) = 0;

    [[nodiscard]] virtual NegotiationState state() const noexcept = 0;

    [[nodiscard]] virtual Result<NegotiationResult> result() const = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// Factory functions
// ─────────────────────────────────────────────────────────────────────────────

std::unique_ptr<INegotiationInitiator>
make_negotiation_initiator(NegotiationConfig config);

std::unique_ptr<INegotiationResponder>
make_negotiation_responder(NegotiationConfig config);

} // namespace uav_pqc::protocol
