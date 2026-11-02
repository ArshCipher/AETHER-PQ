// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file session.hpp
 * @brief Active session state for a single UAV ↔ GCS or UAV ↔ UAV link.
 *
 * A Session is created by the handshake layer after successful authentication
 * and key establishment.  It holds:
 *  - The AEAD session key (send and receive directions)
 *  - The NonceManager for each direction
 *  - Session metadata (ID, peer NodeId, cipher suite, expiry)
 *  - Statistics (bytes encrypted, messages sent/received)
 *
 * Session is a movable value type (not copyable).  Sessions are stored in a
 * SessionCache for resumption and lookup by SessionId.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/crypto/provider.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/session/nonce_manager.hpp"

#include <memory>

namespace uav_pqc::types { class Session; }

namespace uav_pqc::session {

/**
 * @brief Snapshot of session statistics (for monitoring and benchmarking).
 */
struct SessionStats {
    std::uint64_t messages_sent     = 0;
    std::uint64_t messages_received = 0;
    std::uint64_t bytes_encrypted   = 0;
    std::uint64_t bytes_decrypted   = 0;
    std::uint64_t rekey_count       = 0;
    std::uint64_t replay_rejections = 0;
};

/**
 * @brief Active cryptographic session between two nodes.
 *
 * Owns all per-session state: keys, nonces, suite, expiry.
 * Not copyable (owning SecureBytes prevents accidental key duplication).
 */
class Session {
public:
    Session() = default;

    /**
     * @brief Construct a session from key material produced by the handshake.
     *
     * @param id             Session identifier (128-bit random).
     * @param peer_node_id   Verified NodeId of the remote peer.
     * @param suite          Negotiated cipher suite.
     * @param send_key       AEAD key for outbound messages.
     * @param recv_key       AEAD key for inbound messages.
     * @param send_prefix    4-byte nonce prefix for outbound manager.
     * @param recv_prefix    4-byte nonce prefix for inbound manager.
     * @param expiry_ms      Absolute timestamp (monotonic ms) when session expires.
     */
    Session(SessionId                   id,
            NodeId                      peer_node_id,
            protocol::CipherSuite       suite,
            crypto::AeadKey             send_key,
            crypto::AeadKey             recv_key,
            std::array<std::byte, 4>    send_prefix,
            std::array<std::byte, 4>    recv_prefix,
            Timestamp                   expiry_ms,
            std::shared_ptr<crypto::ICryptoProvider> crypto_provider = nullptr);

    ~Session() = default;

    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) noexcept        = default;
    Session& operator=(Session&&) noexcept = default;

    // ── Encryption / decryption ────────────────────────────────────────────────

    /**
     * @brief Encrypt and authenticate plaintext for this session.
     *
     * Internally calls NonceManager::next_nonce() and the configured AEAD.
     * The nonce is prepended to the ciphertext for transmission:
     *   wire = nonce (12 bytes) || ciphertext || tag (16 bytes)
     *
     * @param plaintext   Data to encrypt.
     * @param aad         Additional authenticated data (e.g. message header).
     * @return            Wire-formatted output: nonce || ciphertext || tag.
     */
    [[nodiscard]] Result<Bytes> encrypt(ByteSpan plaintext, ByteSpan aad);

    /**
     * @brief Decrypt and verify an inbound wire message.
     *
     * Extracts the nonce from the first 12 bytes, verifies the tag, checks
     * the nonce against the replay window.
     *
     * @param wire_message  nonce (12) || ciphertext || tag bytes.
     * @param aad           Additional authenticated data (must match sender).
     * @return              Plaintext, or an appropriate error code.
     */
    [[nodiscard]] Result<Bytes> decrypt(ByteSpan wire_message, ByteSpan aad);

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /**
     * @brief Returns true if the session has not expired and nonces are not
     * exhausted.  Check before every send operation.
     */
    [[nodiscard]] bool is_valid(Timestamp now_ms = 0) const noexcept;

    /**
     * @brief Rotate the AEAD keys without full re-handshake.
     *
     * Called when nonces near exhaustion or the rekey timer fires.
     * New keys are derived via HKDF from the current key + a fresh label.
     */
    [[nodiscard]] VoidResult rotate_keys();

    // ── Metadata accessors ────────────────────────────────────────────────────

    [[nodiscard]] const SessionId&              id()            const noexcept { return id_; }
    [[nodiscard]] const NodeId&                 peer_node_id()  const noexcept { return peer_node_id_; }
    [[nodiscard]] const protocol::CipherSuite&  suite()         const noexcept { return suite_; }
    [[nodiscard]] const SessionStats&           stats()         const noexcept { return stats_; }
    [[nodiscard]] Timestamp                     expiry_ms()     const noexcept { return expiry_ms_; }

private:
    friend class ::uav_pqc::types::Session;

    SessionId                       id_{};
    NodeId                          peer_node_id_{};
    protocol::CipherSuite           suite_{};
    crypto::AeadKey                 send_key_;
    crypto::AeadKey                 recv_key_;
    NonceManager                    send_nonces_;
    NonceManager                    recv_nonces_;
    Timestamp                       expiry_ms_ = 0;
    SessionStats                    stats_{};

    std::unique_ptr<crypto::IAead>  aead_;
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider_;
};

} // namespace uav_pqc::session
