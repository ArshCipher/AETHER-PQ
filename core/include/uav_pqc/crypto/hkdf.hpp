// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file hkdf.hpp
 * @brief HKDF (RFC 5869) key derivation via OpenSSL EVP_KDF.
 *
 * Used at two points in the protocol:
 *  1. Hybrid key combination: combine(ML-KEM shared secret, X25519 shared secret)
 *     → AEAD session key.
 *  2. Session key expansion: a single KEM shared secret → multiple symmetric keys
 *     (data key, header key, nonce prefix).
 *
 * Thread safety: Hkdf instances are immutable after construction and may be
 * shared across threads without synchronisation.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstddef>
#include <string_view>

namespace uav_pqc::crypto {

/**
 * @brief Supported hash algorithms for HKDF.
 */
enum class HkdfHash {
    Sha256, ///< HMAC-SHA-256 (default — adequate for 128-bit security)
    Sha384, ///< HMAC-SHA-384
    Sha512, ///< HMAC-SHA-512 (used in Hardened profile)
};

/**
 * @brief HKDF key derivation function (RFC 5869).
 *
 * Provides three operations:
 *  - extract(salt, ikm)          → pseudorandom key (PRK)
 *  - expand(prk, info, length)   → output keying material (OKM)
 *  - derive(salt, ikm, info, length) → combined extract-then-expand
 *
 * All operations are stateless and re-entrant.
 */
class Hkdf {
public:
    /**
     * @brief Construct an Hkdf instance bound to a specific hash.
     * @param hash  Underlying hash algorithm.  Default: SHA-256.
     */
    explicit Hkdf(HkdfHash hash = HkdfHash::Sha256);

    ~Hkdf();

    Hkdf(const Hkdf&)            = delete;
    Hkdf& operator=(const Hkdf&) = delete;
    Hkdf(Hkdf&&) noexcept;
    Hkdf& operator=(Hkdf&&) noexcept;

    // ── HKDF-Extract ──────────────────────────────────────────────────────────

    /**
     * @brief Extract a pseudorandom key from input keying material.
     *
     * HKDF-Extract(salt, IKM) → PRK
     *
     * @param salt  Optional salt value.  Pass an empty span to use the
     *              HKDF default salt (a string of hash_len zeroes).
     * @param ikm   Input keying material.
     * @return      PRK of length hash_output_size() bytes.
     */
    [[nodiscard]] Result<SecureBytes>
    extract(ByteSpan salt, ByteSpan ikm) const;

    // ── HKDF-Expand ───────────────────────────────────────────────────────────

    /**
     * @brief Expand a pseudorandom key into output keying material.
     *
     * HKDF-Expand(PRK, info, L) → OKM
     *
     * @param prk     Pseudorandom key (output of extract).
     * @param info    Context and application-specific information.
     * @param length  Desired OKM length in bytes (≤ 255 × hash_output_size()).
     * @return        OKM of exactly @p length bytes.
     */
    [[nodiscard]] Result<SecureBytes>
    expand(ByteSpan prk, ByteSpan info, std::size_t length) const;

    // ── HKDF combined ─────────────────────────────────────────────────────────

    /**
     * @brief Combined HKDF-Extract-then-Expand in a single call.
     *
     * @param salt    Optional salt (empty → default HKDF salt).
     * @param ikm     Input keying material.
     * @param info    Application-specific context string.
     * @param length  Desired output length in bytes.
     * @return        Output keying material of exactly @p length bytes.
     */
    [[nodiscard]] Result<SecureBytes>
    derive(ByteSpan salt, ByteSpan ikm, ByteSpan info, std::size_t length) const;

    // ── Metadata ──────────────────────────────────────────────────────────────

    /// Number of bytes in the underlying hash output (e.g. 32 for SHA-256).
    [[nodiscard]] std::size_t hash_output_size() const noexcept;

    /// Human-readable identifier (e.g. "HKDF-SHA256").
    [[nodiscard]] std::string_view algorithm_id() const noexcept;

private:
    HkdfHash hash_;
};

} // namespace uav_pqc::crypto
