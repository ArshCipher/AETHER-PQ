// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file aes_gcm.hpp
 * @brief AES-GCM AEAD implementation via OpenSSL EVP_AEAD.
 *
 * Used in:
 *   - Standard profile:  AES-128-GCM or AES-256-GCM
 *   - Hardened profile:  AES-256-GCM exclusively
 *   - Session payload encryption for nodes with hardware AES acceleration
 *     (AES-NI on x86_64, ARMv8 Crypto on aarch64/Cortex-A)
 *
 * Nonce handling:
 *   - 96-bit (12-byte) nonces, as per NIST SP 800-38D recommendation.
 *   - Callers MUST use NonceManager to guarantee uniqueness.
 *   - The nonce is never derived from message content; it always incorporates
 *     a monotonically increasing counter.
 *
 * Thread safety: AesGcm is stateless; multiple threads may call encrypt/decrypt
 * concurrently on the same instance.
 */

#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

namespace uav_pqc::crypto {

/**
 * @brief AES-GCM key length selector.
 */
enum class AesKeyLen {
    Aes128, ///< 128-bit key (16 bytes) — adequate for Standard profile
    Aes256, ///< 256-bit key (32 bytes) — required for Hardened profile
};

/**
 * @brief AES-GCM authenticated encryption via OpenSSL 3 EVP_CIPHER_CTX.
 *
 * The authentication tag is appended to the ciphertext (at offset ciphertext.size()
 * − tag_size()).  decrypt() verifies the tag before returning plaintext.
 */
class AesGcm final : public IAead {
public:
    static constexpr std::size_t kNonceSize = 12; ///< 96-bit nonce
    static constexpr std::size_t kTagSize   = 16; ///< 128-bit authentication tag

    /**
     * @brief Construct an AES-GCM instance.
     * @param key_len  Key length.  Default: Aes256 (32 bytes).
     */
    explicit AesGcm(AesKeyLen key_len = AesKeyLen::Aes256);
    ~AesGcm() override = default;

    AesGcm(const AesGcm&)             = delete;
    AesGcm& operator=(const AesGcm&)  = delete;
    AesGcm(AesGcm&&) noexcept         = default;
    AesGcm& operator=(AesGcm&&) noexcept = default;

    // ── IAead implementation ──────────────────────────────────────────────────

    [[nodiscard]] Result<Bytes>
    encrypt(const AeadKey& key, ByteSpan nonce,
            ByteSpan plaintext, ByteSpan aad) const override;

    [[nodiscard]] Result<Bytes>
    decrypt(const AeadKey& key, ByteSpan nonce,
            ByteSpan ciphertext, ByteSpan aad) const override;

    [[nodiscard]] std::string_view algorithm_id() const noexcept override;
    [[nodiscard]] std::size_t      key_size()     const noexcept override;
    [[nodiscard]] std::size_t      nonce_size()   const noexcept override;
    [[nodiscard]] std::size_t      tag_size()     const noexcept override;

    // ── AesGcm-specific ────────────────────────────────────────────────────────

    [[nodiscard]] AesKeyLen key_len() const noexcept { return key_len_; }

private:
    AesKeyLen key_len_;
};

} // namespace uav_pqc::crypto
