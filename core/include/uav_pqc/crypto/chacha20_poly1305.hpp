// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file chacha20_poly1305.hpp
 * @brief ChaCha20-Poly1305 AEAD implementation via OpenSSL EVP.
 *
 * Preferred on:
 *   - Lightweight profile (small MCUs, software-only crypto)
 *   - Any node WITHOUT hardware AES acceleration
 *   - Standard profile on nodes where software ChaCha20 outperforms AES-GCM
 *
 * Key / nonce sizes:
 *   Key   : 32 bytes (256-bit; ChaCha20 has a single key length)
 *   Nonce : 12 bytes (96-bit IETF ChaCha20-Poly1305, RFC 8439)
 *   Tag   : 16 bytes (128-bit Poly1305 MAC)
 *
 * Thread safety: ChaCha20Poly1305 is stateless; concurrent use is safe.
 */

#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

namespace uav_pqc::crypto {

/**
 * @brief ChaCha20-Poly1305 authenticated encryption via OpenSSL 3 EVP.
 */
class ChaCha20Poly1305 final : public IAead {
public:
    static constexpr std::size_t kKeySize   = 32; ///< 256-bit key
    static constexpr std::size_t kNonceSize = 12; ///< 96-bit nonce (RFC 8439)
    static constexpr std::size_t kTagSize   = 16; ///< 128-bit Poly1305 tag

    ChaCha20Poly1305()                                       = default;
    ~ChaCha20Poly1305() override                             = default;
    ChaCha20Poly1305(const ChaCha20Poly1305&)                = delete;
    ChaCha20Poly1305& operator=(const ChaCha20Poly1305&)     = delete;
    ChaCha20Poly1305(ChaCha20Poly1305&&) noexcept            = default;
    ChaCha20Poly1305& operator=(ChaCha20Poly1305&&) noexcept = default;

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
};

} // namespace uav_pqc::crypto
