// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file aead.hpp
 * @brief Abstract Authenticated Encryption with Associated Data (AEAD) interface.
 *
 * All symmetric cipher implementations (AES-GCM, ChaCha20-Poly1305)
 * implement IAead.  The ACPE selects the concrete implementation based on
 * hardware capability and cryptographic profile; upper layers are agnostic.
 *
 * Security contract:
 *  - Nonces must be unique per (key, nonce) pair.  Use NonceManager to
 *    guarantee uniqueness; never construct nonces manually in protocol code.
 *  - Failed decryption returns ErrorCode::AeadDecryptFailed; the output
 *    buffer is left zeroed — callers must never use partial plaintext.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstddef>
#include <string_view>

namespace uav_pqc::crypto {

// ─────────────────────────────────────────────────────────────────────────────
// AEAD key type
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Symmetric AEAD key.  Always stored in SecureBytes (zeroed on destroy).
 *
 * Key length is algorithm-dependent (16 or 32 bytes for AES-GCM; 32 bytes
 * for ChaCha20-Poly1305).  Construct via HKDF or from a shared secret.
 */
struct AeadKey {
    SecureBytes data;

    [[nodiscard]] bool        empty() const noexcept { return data.empty(); }
    [[nodiscard]] std::size_t size() const noexcept  { return data.size(); }
    [[nodiscard]] ByteSpan    span() const noexcept  { return data.span(); }

    /// Convenience factory from raw bytes (copies into SecureBytes).
    static AeadKey from_bytes(ByteSpan raw) {
        AeadKey k;
        k.data = SecureBytes(Bytes(raw.begin(), raw.end()));
        return k;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// IAead — abstract AEAD interface
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Abstract Authenticated Encryption with Associated Data.
 *
 * Implementations: AesGcm, ChaCha20Poly1305.
 */
class IAead {
public:
    IAead()                              = default;
    IAead(const IAead&)                  = delete;
    IAead& operator=(const IAead&)       = delete;
    IAead(IAead&&) noexcept              = default;
    IAead& operator=(IAead&&) noexcept   = default;
    virtual ~IAead()                     = default;

    // ── Core operations ───────────────────────────────────────────────────────

    /**
     * @brief Encrypt and authenticate plaintext.
     *
     * @param key        Symmetric key (must be key_size() bytes).
     * @param nonce      Per-message nonce (must be nonce_size() bytes).
     * @param plaintext  Data to encrypt.
     * @param aad        Additional authenticated data (not encrypted, but MACed).
     * @return           Ciphertext with appended authentication tag
     *                   (length = plaintext.size() + tag_size()), or Error.
     */
    [[nodiscard]] virtual Result<Bytes>
    encrypt(const AeadKey& key,
            ByteSpan        nonce,
            ByteSpan        plaintext,
            ByteSpan        aad) const = 0;

    /**
     * @brief Decrypt and verify authenticated ciphertext.
     *
     * @param key        Symmetric key (must be key_size() bytes).
     * @param nonce      Nonce used during encryption (must match exactly).
     * @param ciphertext Ciphertext with appended authentication tag.
     * @param aad        Additional authenticated data (must match exactly).
     * @return           Plaintext on success, or ErrorCode::AeadDecryptFailed
     *                   if authentication fails.  Output is zeroed on failure.
     */
    [[nodiscard]] virtual Result<Bytes>
    decrypt(const AeadKey& key,
            ByteSpan        nonce,
            ByteSpan        ciphertext,
            ByteSpan        aad) const = 0;

    // ── Metadata ──────────────────────────────────────────────────────────────

    /// Algorithm identifier string (e.g. "AES-256-GCM", "ChaCha20-Poly1305").
    [[nodiscard]] virtual std::string_view algorithm_id() const noexcept = 0;

    /// Required key length in bytes.
    [[nodiscard]] virtual std::size_t key_size()   const noexcept = 0;

    /// Required nonce length in bytes.
    [[nodiscard]] virtual std::size_t nonce_size() const noexcept = 0;

    /// Authentication tag length in bytes (appended to ciphertext).
    [[nodiscard]] virtual std::size_t tag_size()   const noexcept = 0;
};

} // namespace uav_pqc::crypto
