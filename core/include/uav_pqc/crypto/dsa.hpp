// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file dsa.hpp
 * @brief Abstract Digital Signature Algorithm (DSA) interface.
 *
 * All signature implementations (ML-DSA, ECDSA-P256) implement IDsa.
 * Protocol code depends only on IDsa to allow mock injection and algorithm
 * substitution without protocol-layer changes.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstddef>
#include <string_view>

namespace uav_pqc::crypto {

// ─────────────────────────────────────────────────────────────────────────────
// DSA key and signature types
// ─────────────────────────────────────────────────────────────────────────────

/// Owning public key for a DSA scheme.  Safe to serialize and distribute.
struct DsaPublicKey {
    Bytes data;

    [[nodiscard]] bool        empty() const noexcept { return data.empty(); }
    [[nodiscard]] std::size_t size() const noexcept  { return data.size(); }
    [[nodiscard]] ByteSpan    span() const noexcept  { return data; }
};

/// Owning private key for a DSA scheme.  SecureBytes; zeroed on destruction.
struct DsaPrivateKey {
    SecureBytes data;

    [[nodiscard]] bool        empty() const noexcept { return data.empty(); }
    [[nodiscard]] std::size_t size() const noexcept  { return data.size(); }
    [[nodiscard]] ByteSpan    span() const noexcept  { return data.span(); }
};

/// Signature produced by sign(); transmitted with the signed message.
struct Signature {
    Bytes data;

    [[nodiscard]] bool        empty() const noexcept { return data.empty(); }
    [[nodiscard]] std::size_t size() const noexcept  { return data.size(); }
    [[nodiscard]] ByteSpan    span() const noexcept  { return data; }
};

/// Key pair produced by generate_keypair().
struct DsaKeyPair {
    DsaPublicKey  public_key;
    DsaPrivateKey private_key;
};

// ─────────────────────────────────────────────────────────────────────────────
// IDsa — abstract DSA interface
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Abstract Digital Signature Algorithm.
 *
 * Implementations: MlDsa, EcdsaP256.  For hybrid authentication both are
 * composed by the protocol layer — IDsa itself remains atomic.
 */
class IDsa {
public:
    IDsa()                             = default;
    IDsa(const IDsa&)                  = delete;
    IDsa& operator=(const IDsa&)       = delete;
    IDsa(IDsa&&) noexcept              = default;
    IDsa& operator=(IDsa&&) noexcept   = default;
    virtual ~IDsa()                    = default;

    // ── Core operations ───────────────────────────────────────────────────────

    /**
     * @brief Generate a fresh signing key pair.
     */
    [[nodiscard]] virtual Result<DsaKeyPair> generate_keypair() const = 0;

    /**
     * @brief Sign a message with a private key.
     *
     * @param private_key  Signing key.
     * @param message      Arbitrary byte sequence to sign.
     * @return Signature, or Error on failure.
     */
    [[nodiscard]] virtual Result<Signature>
    sign(const DsaPrivateKey& private_key, ByteSpan message) const = 0;

    /**
     * @brief Verify a signature against a public key and message.
     *
     * @param public_key   Claimed signer's public key.
     * @param message      Message that was signed.
     * @param signature    Signature to verify.
     * @return true (wrapped in Result) if valid, ErrorCode::VerificationFailed otherwise.
     */
    [[nodiscard]] virtual Result<bool>
    verify(const DsaPublicKey& public_key,
           ByteSpan            message,
           const Signature&    signature) const = 0;

    // ── Metadata ──────────────────────────────────────────────────────────────

    /// IANA/OQS algorithm identifier string (e.g. "ML-DSA-65", "ECDSA-P256").
    [[nodiscard]] virtual std::string_view algorithm_id() const noexcept = 0;

    /// Serialised byte length of a public key.
    [[nodiscard]] virtual std::size_t public_key_size()    const noexcept = 0;

    /// Serialised byte length of a private key.
    [[nodiscard]] virtual std::size_t private_key_size()   const noexcept = 0;

    /// Maximum serialised byte length of a signature (actual length may vary).
    [[nodiscard]] virtual std::size_t max_signature_size() const noexcept = 0;
};

} // namespace uav_pqc::crypto
