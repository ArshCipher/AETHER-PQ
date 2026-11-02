// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file session_establishment.hpp
 * @brief High-level session establishment interface.
 *
 * ISessionEstablisher orchestrates the complete sequence needed to bring a
 * Session into existence from a cold-start:
 *
 *   1. KEM ephemeral key generation (inside IHandshake::start())
 *   2. KEM encapsulation / decapsulation
 *   3. HKDF key derivation (produce AEAD send+recv keys + nonce prefixes)
 *   4. Mutual authentication (certificate exchange + DSA signatures)
 *   5. Finished MAC binding (transcript integrity)
 *   6. Session object construction
 *
 * This interface exists so that callers (benchmarks, integration tests,
 * the ns-3 simulation hook, and the Raspberry Pi daemon) can drive a complete
 * session from a single type without depending on IHandshake internals.
 *
 * Usage — synchronous (in-process) pair:
 * @code
 *   auto init = make_session_establisher(HandshakeRole::Initiator, cfg);
 *   auto resp = make_session_establisher(HandshakeRole::Responder,  cfg);
 *
 *   init->set_send_fn([&](Bytes b) { return resp->feed_message(b); });
 *   resp->set_send_fn([&](Bytes b) { return init->feed_message(b); });
 *
 *   auto r = init->start();   // drives the entire exchange synchronously
 *   assert(init->state() == EstablishmentState::Complete);
 *   auto result = init->result().value();
 * @endcode
 *
 * Thread safety: individual instances are NOT thread-safe.  Use one instance
 * per thread or protect with an external mutex.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/protocol/handshake.hpp"
#include "uav_pqc/crypto/provider.hpp"
#include "uav_pqc/session/session.hpp"

#include <functional>
#include <memory>

namespace uav_pqc::protocol {

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────

enum class EstablishmentState : std::uint8_t {
    Idle      = 0, ///< Not started
    Running   = 1, ///< In progress (messages being exchanged)
    Complete  = 2, ///< Session successfully established
    Failed    = 3, ///< Unrecoverable error; discard and create new establisher
};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief All configuration required to establish a session in any mode.
 *
 * Wraps HandshakeConfig with additional identity hints.  The concrete operating
 * mode is decided by peer-negotiation; all relevant key material must be present
 * regardless of anticipated mode.
 */
struct EstablishmentConfig {
    HandshakeConfig handshake; ///< KEM selection, certificate, DSA keys, CA anchors

    /// Session lifetime cap; 0 means use the handshake default (1 hour).
    Timestamp session_lifetime_ms = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// Result
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Output of a successfully completed session establishment.
 */
struct EstablishmentResult {
    session::Session session;         ///< Ready to encrypt/decrypt
    NodeId           peer_node_id;    ///< Verified remote identity
    OperatingMode    negotiated_mode; ///< Agreed operating mode
    CipherSuite      negotiated_suite;///< Full algorithm selection
};

// ─────────────────────────────────────────────────────────────────────────────
// ISessionEstablisher
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Abstract session establishment state machine.
 *
 * Drives the full cryptographic handshake for all four operating modes
 * (Classical, Transition, Hybrid, PQC-Only).  Callers feed received wire bytes
 * via feed_message() and transmit outgoing bytes via the registered send_fn.
 */
class ISessionEstablisher {
public:
    /// Callback invoked whenever this side needs to transmit a wire message.
    using SendFn = std::function<VoidResult(Bytes message)>;

    ISessionEstablisher()                                          = default;
    ISessionEstablisher(const ISessionEstablisher&)                = delete;
    ISessionEstablisher& operator=(const ISessionEstablisher&)     = delete;
    ISessionEstablisher(ISessionEstablisher&&) noexcept            = default;
    ISessionEstablisher& operator=(ISessionEstablisher&&) noexcept = default;
    virtual ~ISessionEstablisher()                                 = default;

    /**
     * @brief Register the wire-send callback.
     *
     * Must be called before start().  The callback is invoked synchronously
     * within feed_message() calls; it must not re-enter any method on this object.
     */
    virtual void set_send_fn(SendFn fn) = 0;

    /**
     * @brief Begin the handshake (Initiator role only).
     *
     * Generates an ephemeral KEM key pair and sends the first wire message
     * (ClientHello) by invoking the registered send_fn.
     *
     * For the Responder role, this is a no-op — the Responder waits for the
     * first message from the Initiator.
     *
     * @return Ok on success.  Returns an error if called on a Responder or
     *         if the handshake cannot be started (e.g., missing send_fn).
     */
    [[nodiscard]] virtual VoidResult start() = 0;

    /**
     * @brief Process a received wire message.
     *
     * Advances the state machine.  When the handshake completes, state()
     * transitions to EstablishmentState::Complete and result() becomes valid.
     *
     * @param wire_bytes  Raw bytes received from the peer.
     * @return Ok if the message was accepted; an error otherwise.
     */
    [[nodiscard]] virtual VoidResult feed_message(ByteSpan wire_bytes) = 0;

    /// Current observable state.
    [[nodiscard]] virtual EstablishmentState state() const noexcept = 0;

    /**
     * @brief Retrieve the established session.
     *
     * Valid only when state() == EstablishmentState::Complete.
     * Calling this a second time moves the Session out — the establisher is
     * consumed and must be discarded.
     *
     * @return EstablishmentResult on success, ErrorCode::UnsupportedOperation
     *         if the handshake has not completed.
     */
    [[nodiscard]] virtual Result<EstablishmentResult> result() = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Construct a new session establisher.
 *
 * @param role    Whether this instance acts as Initiator (sends first) or
 *                Responder (waits for first message).
 * @param config  All configuration needed for the full handshake.
 * @return        A ready-to-use ISessionEstablisher.
 */
[[nodiscard]] std::unique_ptr<ISessionEstablisher>
make_session_establisher(HandshakeRole role, EstablishmentConfig config, std::shared_ptr<crypto::ICryptoProvider> crypto_provider = nullptr);

} // namespace uav_pqc::protocol
