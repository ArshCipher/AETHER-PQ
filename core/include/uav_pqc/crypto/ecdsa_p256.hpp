// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file ecdsa_p256.hpp
 * @brief ECDSA over NIST P-256 digital signature implementation via OpenSSL EVP.
 *
 * Used in:
 *   - Classical Mode:   sole authentication scheme
 *   - Transition Mode:  authentication with existing PKI certificates
 *   - Hybrid Mode:      classical authentication component alongside ML-DSA-65
 *
 * Key sizes:
 *   Public key   : 65 bytes (uncompressed SEC1 point, 0x04 prefix)
 *   Private key  : 32 bytes (big-endian scalar)
 *   Signature    : 71-72 bytes (DER-encoded ASN.1 SEQUENCE)
 *
 * Implementation uses OpenSSL 3 EVP_DigestSign / EVP_DigestVerify with
 * SHA-256 as the hash function.  All memory is RAII-managed.
 */

#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

namespace uav_pqc::crypto {

/**
 * @brief ECDSA over NIST P-256 with SHA-256, wrapping OpenSSL EVP.
 */
class EcdsaP256 final : public IDsa {
public:
    EcdsaP256()                                = default;
    ~EcdsaP256() override                      = default;
    EcdsaP256(const EcdsaP256&)                = delete;
    EcdsaP256& operator=(const EcdsaP256&)     = delete;
    EcdsaP256(EcdsaP256&&) noexcept            = default;
    EcdsaP256& operator=(EcdsaP256&&) noexcept = default;

    // ── IDsa implementation ───────────────────────────────────────────────────

    [[nodiscard]] Result<DsaKeyPair> generate_keypair()                           const override;
    [[nodiscard]] Result<Signature>  sign(const DsaPrivateKey& sk, ByteSpan msg)  const override;
    [[nodiscard]] Result<bool>       verify(const DsaPublicKey& pk, ByteSpan msg,
                                            const Signature& sig)                  const override;

    [[nodiscard]] std::string_view algorithm_id()       const noexcept override;
    [[nodiscard]] std::size_t      public_key_size()    const noexcept override;
    [[nodiscard]] std::size_t      private_key_size()   const noexcept override;
    [[nodiscard]] std::size_t      max_signature_size() const noexcept override;

    // ── ECDSA-specific helpers ─────────────────────────────────────────────────

    /**
     * @brief Import a public key from an X.509 SubjectPublicKeyInfo DER blob.
     *
     * Useful when consuming certificates produced by a classical CA.
     *
     * @param der  DER-encoded SPKI bytes.
     * @return     Populated DsaPublicKey in SEC1 uncompressed form.
     */
    [[nodiscard]] Result<DsaPublicKey> import_public_key_from_der(ByteSpan der) const;

    /**
     * @brief Export the public key to X.509 SubjectPublicKeyInfo DER format.
     *
     * @param pk  SEC1 uncompressed public key.
     * @return    DER-encoded SPKI bytes.
     */
    [[nodiscard]] Result<Bytes> export_public_key_to_der(const DsaPublicKey& pk) const;
};

} // namespace uav_pqc::crypto
