// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file handshake.hpp
 * @brief Handshake state machine interface.
 *
 * The handshake is the control-plane protocol that establishes a secure
 * session between two nodes (UAV ↔ GCS, or UAV ↔ UAV).  It is separated
 * from the session layer so the session layer can be unit-tested with a
 * pre-established key without running the full handshake.
 *
 * The state machine operates in one of two roles:
 *   HandshakeRole::Initiator — sends ClientHello first (UAV)
 *   HandshakeRole::Responder — receives ClientHello first (GCS)
 *
 * Message flow for each mode is:
 *   Initiator → ClientHello
 *   Responder → ServerHello
 *   Initiator → ClientAuth (certificate + signature)
 *   Responder → ServerAuth (certificate + signature)
 *   Initiator → HandshakeFinished
 *   Responder → HandshakeFinished
 *
 * Authentication is ALWAYS completed before key material is exchanged with
 * the application layer, preventing unauthenticated KEM operations.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/protocol/mode.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/protocol/message.hpp"
#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/crypto/provider.hpp"
#include "uav_pqc/session/session.hpp"

#include <functional>
#include <memory>

namespace uav_pqc::protocol {

/// Handshake role for this node in the current session.
enum class HandshakeRole : std::uint8_t {
    Initiator = 0, ///< UAV — sends ClientHello
    Responder = 1, ///< GCS — receives ClientHello
};

/// Observable state of the handshake state machine.
enum class HandshakeState : std::uint8_t {
    Idle           = 0, ///< Not started
    WaitServerHello= 1, ///< Initiator waiting for ServerHello
    WaitClientAuth = 2, ///< Responder waiting for ClientAuth
    WaitServerAuth = 3, ///< Initiator waiting for ServerAuth
    WaitFinished   = 4, ///< Either side waiting for HandshakeFinished
    Complete       = 5, ///< Handshake successful; session key is available
    Failed         = 6, ///< Handshake failed; must restart
};

/**
 * @brief Configuration for a handshake execution.
 */
struct HandshakeConfig {
    /// List of modes this node is willing to accept (priority order).
    std::vector<OperatingMode> offered_modes;

    /// Maximum time in milliseconds before a waiting state times out.
    /// Extended for PQC to accommodate fragment latency on lossy RF links.
    std::uint32_t timeout_ms = 10000; // 10 seconds default

    /// Maximum number of retransmissions for a single fragment.
    std::uint8_t max_retransmissions = 5;

    /// Our long-term certificate (DER bytes, used in AuthMessage).
    Bytes our_certificate;

    /// Our long-term DSA private key (for signing the transcript).
    crypto::DsaPrivateKey our_dsa_private_key;

    /// Our long-term ML-DSA private key (for hybrid signing; may be empty).
    crypto::DsaPrivateKey our_ml_dsa_private_key;

    /// Trusted CA certificate(s) for verifying the peer's certificate chain.
    std::vector<Bytes> trusted_ca_certs;

    /// NodeId of this node (derived from long-term public key).
    NodeId our_node_id{};
};

/**
 * @brief Result of a successfully completed handshake.
 *
 * The session key and cipher suite are handed to the Session layer.
 */
struct HandshakeResult {
    session::Session   session;     ///< Fully initialised session
    NodeId             peer_node_id; ///< Verified identity of the remote peer
    OperatingMode      negotiated_mode;
    CipherSuite        negotiated_suite;
};

/**
 * @brief Abstract handshake state machine.
 *
 * Concrete implementations are not yet provided (protocol logic phase).
 * The interface is fully specified here so the session layer and tests can
 * compile against it.
 *
 * Callback-driven: the caller feeds incoming wire bytes via feed_message()
 * and transmits outgoing bytes via the registered send_fn.
 */
class IHandshake {
public:
    /// Callback invoked when this side needs to send bytes on the channel.
    using SendFn = std::function<VoidResult(Bytes message)>;

    IHandshake()                                 = default;
    IHandshake(const IHandshake&)                = delete;
    IHandshake& operator=(const IHandshake&)     = delete;
    IHandshake(IHandshake&&) noexcept            = default;
    IHandshake& operator=(IHandshake&&) noexcept = default;
    virtual ~IHandshake()                         = default;

    /**
     * @brief Start the handshake.
     *
     * For Initiator: immediately produces and sends a ClientHello.
     * For Responder: enters waiting state.
     */
    [[nodiscard]] virtual VoidResult start() = 0;

    /**
     * @brief Feed a received wire message into the state machine.
     *
     * Returns Ok if the message was processed successfully.
     * Returns an error if the message is unexpected, malformed, or triggers
     * an authentication failure.
     *
     * If the handshake completes as a result of this call, state() returns
     * HandshakeState::Complete and result() is populated.
     */
    [[nodiscard]] virtual VoidResult feed_message(ByteSpan wire_bytes) = 0;

    /// Returns the current observable state.
    [[nodiscard]] virtual HandshakeState state() const noexcept = 0;

    /**
     * @brief Returns the handshake result.
     *
     * Valid only when state() == HandshakeState::Complete.
     * Returns ErrorCode::UnsupportedOperation in any other state.
     */
    [[nodiscard]] virtual Result<HandshakeResult> result() = 0;

    /// Register the send callback before calling start().
    virtual void set_send_fn(SendFn fn) = 0;

    /// Get negotiated operating mode (valid after ServerHello is processed).
    [[nodiscard]] virtual OperatingMode get_negotiated_mode() const noexcept = 0;
};

/**
 * @brief Factory function to construct a new Handshake instance.
 */
std::unique_ptr<IHandshake> make_handshake(HandshakeRole role, HandshakeConfig config, std::shared_ptr<crypto::ICryptoProvider> crypto_provider = nullptr);

} // namespace uav_pqc::protocol
