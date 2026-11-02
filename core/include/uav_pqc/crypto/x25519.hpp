// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file x25519.hpp
 * @brief X25519 Diffie-Hellman key exchange wrapped as a KEM, via OpenSSL EVP.
 *
 * X25519 is used in Classical Mode and Hybrid Mode as the classical component.
 * Wrapping it as IKem allows the hybrid combiner to compose it with ML-KEM
 * through a uniform interface.
 *
 * Key sizes:
 *   Public key  : 32 bytes
 *   Private key : 32 bytes
 *   Shared secret: 32 bytes
 *
 * The "ciphertext" in KEM terms is the encapsulator's ephemeral public key
 * (32 bytes), which is sent to the decapsulator so it can compute the same
 * shared secret.  This matches the RFC 7748 ECDH flow adapted to a KEM API.
 */

#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

namespace uav_pqc::crypto {

/**
 * @brief X25519 key exchange wrapped as a KEM (IKem).
 *
 * Uses OpenSSL 3 EVP_PKEY_CTX with the "X25519" key type.  All memory
 * management is RAII; no raw EVP handles escape this class.
 */
class X25519Kem final : public IKem {
public:
    X25519Kem()                              = default;
    ~X25519Kem() override                    = default;
    X25519Kem(const X25519Kem&)              = delete;
    X25519Kem& operator=(const X25519Kem&)   = delete;
    X25519Kem(X25519Kem&&) noexcept          = default;
    X25519Kem& operator=(X25519Kem&&) noexcept = default;

    // ── IKem implementation ───────────────────────────────────────────────────

    [[nodiscard]] Result<KemKeyPair>          generate_keypair()                    const override;
    [[nodiscard]] Result<KemKeyPair>          generate_keypair_deterministic(ByteSpan seed) const override;
    [[nodiscard]] Result<EncapsulationResult> encapsulate(const KemPublicKey& pk)   const override;
    [[nodiscard]] Result<SharedSecret>        decapsulate(const KemPrivateKey& sk,
                                                          const KemCiphertext& ct)  const override;

    [[nodiscard]] std::string_view algorithm_id()       const noexcept override;
    [[nodiscard]] std::size_t      public_key_size()    const noexcept override;
    [[nodiscard]] std::size_t      private_key_size()   const noexcept override;
    [[nodiscard]] std::size_t      ciphertext_size()    const noexcept override;
    [[nodiscard]] std::size_t      shared_secret_size() const noexcept override;

    // ── X25519-specific helpers ────────────────────────────────────────────────

    /**
     * @brief Perform raw X25519 DH (not wrapped as KEM).
     *
     * Useful when the caller owns both sides of the key material and needs
     * the raw shared secret without the ephemeral-key encapsulation layer.
     *
     * @param private_key  Local private key (32 bytes, RFC 7748 format).
     * @param peer_public  Remote public key (32 bytes).
     * @return             32-byte shared secret (before HKDF).
     */
    [[nodiscard]] Result<SharedSecret>
    raw_dh(const KemPrivateKey& private_key,
           const KemPublicKey&  peer_public) const;
};

} // namespace uav_pqc::crypto
