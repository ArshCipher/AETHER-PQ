// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file hybrid_kem.hpp
 * @brief Hybrid ML-KEM-768 + X25519 Key Encapsulation Mechanism.
 *
 * Implements Hybrid Mode key establishment as specified in the architecture:
 *
 *   combined_secret = ML-KEM-768-SS || X25519-SS
 *   session_key     = HKDF-SHA256(salt=∅, ikm=combined_secret, info=context)
 *
 * Both KEM operations run independently; their shared secrets are concatenated
 * before HKDF.  The security argument: an attacker must break BOTH ML-KEM
 * (lattice hardness) AND X25519 (ECDLP) to obtain the session key.
 *
 * Wire format of the hybrid "ciphertext" (KemCiphertext.data):
 *   [0..1087]   ML-KEM-768 ciphertext (1088 bytes)
 *   [1088..1119] X25519 ephemeral public key (32 bytes)
 *   total: 1120 bytes
 *
 * Wire format of the hybrid public key (KemPublicKey.data):
 *   [0..1183]   ML-KEM-768 public key (1184 bytes)
 *   [1184..1215] X25519 static public key (32 bytes)
 *   total: 1216 bytes
 *
 * Thread safety: HybridKem is stateless after construction.
 */

#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/x25519.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <string_view>

namespace uav_pqc::crypto {

/**
 * @brief Hybrid KEM composing ML-KEM-768 and X25519.
 *
 * Conforms to IKem so it can be used transparently wherever a KEM is expected.
 * The underlying ML-KEM level is fixed at Kem768 to match the Standard profile;
 * a Hardened-profile variant with Kem1024 can be created by subclassing if needed.
 */
class HybridKem final : public IKem {
public:
    /**
     * @brief Construct the hybrid KEM.
     *
     * @param context  HKDF info string binding the derived key to a protocol
     *                 context (e.g. "uav_pqc hybrid-kem-768-x25519 v1").
     *                 Must be non-empty and immutable for the lifetime of this object.
     */
    explicit HybridKem(std::string_view context = "uav_pqc hybrid-kem-768-x25519 v1");
    ~HybridKem() override = default;

    HybridKem(const HybridKem&)             = delete;
    HybridKem& operator=(const HybridKem&)  = delete;
    HybridKem(HybridKem&&) noexcept         = default;
    HybridKem& operator=(HybridKem&&) noexcept = default;

    // ── IKem implementation ───────────────────────────────────────────────────

    /**
     * @brief Generate a hybrid key pair (ML-KEM-768 || X25519).
     *
     * The returned KemPublicKey.data is the concatenation of both public keys.
     * The returned KemPrivateKey.data is the concatenation of both private keys.
     */
    [[nodiscard]] Result<KemKeyPair>          generate_keypair()                          const override;
    [[nodiscard]] Result<KemKeyPair>          generate_keypair_deterministic(ByteSpan seed) const override;
    [[nodiscard]] Result<EncapsulationResult> encapsulate(const KemPublicKey& pk)         const override;
    [[nodiscard]] Result<SharedSecret>        decapsulate(const KemPrivateKey& sk,
                                                          const KemCiphertext& ct)        const override;

    [[nodiscard]] std::string_view algorithm_id()       const noexcept override;
    [[nodiscard]] std::size_t      public_key_size()    const noexcept override;
    [[nodiscard]] std::size_t      private_key_size()   const noexcept override;
    [[nodiscard]] std::size_t      ciphertext_size()    const noexcept override;
    [[nodiscard]] std::size_t      shared_secret_size() const noexcept override;

    // ── HybridKem-specific ────────────────────────────────────────────────────

    /// Size of the ML-KEM-768 public key component (1184 bytes).
    [[nodiscard]] std::size_t mlkem_public_key_size()  const noexcept;

    /// Size of the X25519 public key component (32 bytes).
    [[nodiscard]] std::size_t x25519_public_key_size() const noexcept;

private:
    MlKem       mlkem_;
    X25519Kem   x25519_;
    Hkdf        hkdf_;
    std::string context_;
};

} // namespace uav_pqc::crypto
