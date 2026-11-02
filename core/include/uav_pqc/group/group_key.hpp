// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file group_key.hpp
 * @brief Group symmetric key type for swarm broadcast encryption.
 *
 * A GroupKey is a 32-byte symmetric key shared among all current swarm members.
 * It is loaded directly into the AEAD engine to encrypt broadcast traffic
 * (telemetry, position broadcasts, swarm coordination, collision beacons).
 *
 * Key rotation is triggered by TreeKEM on membership change.  Each rotation
 * increments the GroupEpoch; stale-epoch messages are rejected.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/protocol/suite.hpp"

#include <cstdint>

namespace uav_pqc::crypto { class ICryptoProvider; }

namespace uav_pqc::group {

/**
 * @brief A single group key epoch.
 *
 * Immutable after construction.  The key bytes are stored in SecureBytes.
 */
class GroupKey {
public:
    static constexpr std::size_t kKeySize = 32; ///< 256-bit group key

    /**
     * @brief Construct from raw key material.
     *
     * @param epoch     Epoch number (monotonically increasing).
     * @param key_bytes 32-byte symmetric key material.
     * @param suite     Cipher suite specifying which AEAD algorithm to use.
     * @param issued_ms Timestamp when this key was issued.
     * @param expiry_ms Timestamp when this key expires (and must be rotated).
     */
    GroupKey(GroupEpoch              epoch,
             SecureBytes             key_bytes,
             protocol::AeadAlgorithm algorithm,
             Timestamp               issued_ms,
             Timestamp               expiry_ms);

    ~GroupKey() = default;
    GroupKey(const GroupKey&)            = delete;
    GroupKey& operator=(const GroupKey&) = delete;
    GroupKey(GroupKey&&) noexcept        = default;
    GroupKey& operator=(GroupKey&&) noexcept = default;

    // ── Encryption / decryption ────────────────────────────────────────────────

    /**
     * @brief Encrypt a broadcast payload using this group key.
     *
     * Nonce is constructed from epoch (4 bytes) + message counter (8 bytes).
     * The message counter must be supplied by the caller to guarantee uniqueness.
     *
     * @param plaintext       Broadcast message body.
     * @param aad             Associated data (e.g. message header bytes).
     * @param message_counter Per-epoch message counter (must be unique per sender).
     * @param provider        Optional cryptographic provider for abstraction.
     */
    [[nodiscard]] Result<Bytes>
    encrypt(ByteSpan plaintext, ByteSpan aad, std::uint64_t message_counter, const crypto::ICryptoProvider* provider = nullptr) const;

    /**
     * @brief Decrypt a broadcast payload.
     *
     * @param ciphertext      Received ciphertext (nonce || body || tag).
     * @param aad             Associated data (must match sender).
     * @param message_counter Must match the value used during encryption.
     * @param provider        Optional cryptographic provider for abstraction.
     */
    [[nodiscard]] Result<Bytes>
    decrypt(ByteSpan ciphertext, ByteSpan aad, std::uint64_t message_counter, const crypto::ICryptoProvider* provider = nullptr) const;

    // ── Accessors ─────────────────────────────────────────────────────────────

    [[nodiscard]] GroupEpoch              epoch()     const noexcept { return epoch_; }
    [[nodiscard]] protocol::AeadAlgorithm algorithm() const noexcept { return algorithm_; }
    [[nodiscard]] Timestamp               issued_ms() const noexcept { return issued_ms_; }
    [[nodiscard]] Timestamp               expiry_ms() const noexcept { return expiry_ms_; }
    [[nodiscard]] bool is_expired(Timestamp now_ms)   const noexcept { return now_ms >= expiry_ms_; }

    /// Returns the AeadKey view for direct AEAD use.
    [[nodiscard]] crypto::AeadKey make_aead_key() const;
    [[nodiscard]] GroupKey clone() const;

private:
    GroupEpoch              epoch_;
    SecureBytes             key_bytes_;
    protocol::AeadAlgorithm algorithm_;
    Timestamp               issued_ms_;
    Timestamp               expiry_ms_;
};

} // namespace uav_pqc::group
