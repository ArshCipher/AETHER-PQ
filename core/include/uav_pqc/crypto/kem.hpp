// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file kem.hpp
 * @brief Abstract Key Encapsulation Mechanism (KEM) interface.
 *
 * All KEM implementations (ML-KEM, X25519 used as KEM, hybrid) implement
 * this interface.  Protocol code depends only on IKem, never on a concrete
 * type, enabling clean substitution and mock injection in tests.
 *
 * Key type vocabulary:
 *   KemPublicKey  — may be shared freely
 *   KemPrivateKey — stored in SecureBytes; zeroed on destruction
 *   KemCiphertext — the encapsulation result sent to the decapsulator
 *   SharedSecret  — 32-byte uniformly random key material; zeroed on destroy
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstddef>
#include <string_view>

namespace uav_pqc::crypto {

// ─────────────────────────────────────────────────────────────────────────────
// KEM key and output types
// ─────────────────────────────────────────────────────────────────────────────

/// Owning public key for a KEM scheme.  Safe to copy and serialize.
struct KemPublicKey {
    Bytes data;

    [[nodiscard]] bool      empty() const noexcept { return data.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return data.size(); }
    [[nodiscard]] ByteSpan  span() const noexcept { return data; }
};

/// Owning private key for a KEM scheme.  Stored securely; zeroed on destruction.
struct KemPrivateKey {
    SecureBytes data;

    [[nodiscard]] bool        empty() const noexcept { return data.empty(); }
    [[nodiscard]] std::size_t size() const noexcept  { return data.size(); }
    [[nodiscard]] ByteSpan    span() const noexcept  { return data.span(); }
};

/// Ciphertext produced by encapsulate(); sent to the decapsulator.
struct KemCiphertext {
    Bytes data;

    [[nodiscard]] bool        empty() const noexcept { return data.empty(); }
    [[nodiscard]] std::size_t size() const noexcept  { return data.size(); }
    [[nodiscard]] ByteSpan    span() const noexcept  { return data; }
};

/**
 * @brief Shared secret output from KEM encapsulation or decapsulation.
 *
 * Always exactly shared_secret_size() bytes.  The underlying storage is
 * SecureBytes so it is zeroed when this struct goes out of scope.
 */
struct SharedSecret {
    SecureBytes data;

    [[nodiscard]] bool        empty() const noexcept { return data.empty(); }
    [[nodiscard]] std::size_t size() const noexcept  { return data.size(); }
    [[nodiscard]] ByteSpan    span() const noexcept  { return data.span(); }
};

/// Key pair produced by generate_keypair().
struct KemKeyPair {
    KemPublicKey  public_key;
    KemPrivateKey private_key;
};

/// Encapsulation result: the shared secret and the ciphertext to send.
struct EncapsulationResult {
    SharedSecret  shared_secret; ///< Keep locally; derive session key from this
    KemCiphertext ciphertext;    ///< Send to the decapsulator
};

// ─────────────────────────────────────────────────────────────────────────────
// IKem — abstract KEM interface
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Abstract Key Encapsulation Mechanism.
 *
 * Implementations: MlKem, X25519Kem (OpenSSL), HybridKem (ML-KEM + X25519).
 */
class IKem {
public:
    IKem()                             = default;
    IKem(const IKem&)                  = delete;
    IKem& operator=(const IKem&)       = delete;
    IKem(IKem&&) noexcept              = default;
    IKem& operator=(IKem&&) noexcept   = default;
    virtual ~IKem()                    = default;

    // ── Core operations ───────────────────────────────────────────────────────

    /**
     * @brief Generate a fresh KEM key pair.
     * @return KeyPair on success, Error on RNG or library failure.
     */
    [[nodiscard]] virtual Result<KemKeyPair> generate_keypair() const = 0;

    /**
     * @brief Generate a KEM key pair from a seed.
     * @return KeyPair on success, Error on seed length or library failure.
     */
    [[nodiscard]] virtual Result<KemKeyPair> generate_keypair_deterministic(ByteSpan seed) const = 0;

    /**
     * @brief Encapsulate a shared secret to a recipient's public key.
     *
     * The caller keeps shared_secret and sends ciphertext to the recipient.
     *
     * @param public_key  Recipient's public key.
     * @return EncapsulationResult, or Error if the public key is malformed.
     */
    [[nodiscard]] virtual Result<EncapsulationResult>
    encapsulate(const KemPublicKey& public_key) const = 0;

    /**
     * @brief Recover the shared secret from a ciphertext using a private key.
     *
     * @param private_key  The recipient's private key.
     * @param ciphertext   The ciphertext produced by encapsulate().
     * @return SharedSecret, or ErrorCode::DecapsulationFailed if invalid.
     */
    [[nodiscard]] virtual Result<SharedSecret>
    decapsulate(const KemPrivateKey& private_key,
                const KemCiphertext& ciphertext) const = 0;

    // ── Metadata ──────────────────────────────────────────────────────────────

    /// IANA/OQS algorithm identifier string (e.g. "ML-KEM-768").
    [[nodiscard]] virtual std::string_view algorithm_id() const noexcept = 0;

    /// Serialised byte length of a public key.
    [[nodiscard]] virtual std::size_t public_key_size()    const noexcept = 0;

    /// Serialised byte length of a private key.
    [[nodiscard]] virtual std::size_t private_key_size()   const noexcept = 0;

    /// Serialised byte length of a ciphertext.
    [[nodiscard]] virtual std::size_t ciphertext_size()    const noexcept = 0;

    /// Byte length of the shared secret output (always 32 for ML-KEM).
    [[nodiscard]] virtual std::size_t shared_secret_size() const noexcept = 0;
};

} // namespace uav_pqc::crypto
