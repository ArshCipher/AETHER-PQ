// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file credential_store.hpp
 * @brief Persistent credential storage interface for UAV and GCS nodes.
 *
 * The credential store holds:
 *  - The node's long-term identity key pair (ECDSA-P256 and/or ML-DSA)
 *  - The node's certificate chain
 *  - The current leaf KEM key pair (for TreeKEM)
 *  - Trusted CA anchor certificates
 *
 * Access to private key material is gated behind an access policy; on
 * production hardware this interface should delegate to a hardware security
 * module (HSM) or the platform's secure element.
 *
 * The abstract interface enables test injection with in-memory stores and
 * future integration with TPM/HSM backends.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/identity/certificate.hpp"

#include <memory>
#include <vector>

namespace uav_pqc::identity {

/**
 * @brief Abstract credential store.
 */
class ICredentialStore {
public:
    ICredentialStore()                                       = default;
    ICredentialStore(const ICredentialStore&)                = delete;
    ICredentialStore& operator=(const ICredentialStore&)     = delete;
    ICredentialStore(ICredentialStore&&) noexcept            = default;
    ICredentialStore& operator=(ICredentialStore&&) noexcept = default;
    virtual ~ICredentialStore()                               = default;

    // ── Identity ──────────────────────────────────────────────────────────────

    [[nodiscard]] virtual NodeId                     our_node_id()       const = 0;
    [[nodiscard]] virtual const Certificate&         our_certificate()   const = 0;
    [[nodiscard]] virtual const crypto::DsaPrivateKey& ecdsa_private_key() const = 0;
    [[nodiscard]] virtual const crypto::DsaPrivateKey& ml_dsa_private_key() const = 0;
    [[nodiscard]] virtual const crypto::DsaPublicKey&  ecdsa_public_key() const = 0;
    [[nodiscard]] virtual const crypto::DsaPublicKey&  ml_dsa_public_key() const = 0;

    // ── Leaf KEM key (for TreeKEM) ────────────────────────────────────────────

    [[nodiscard]] virtual const crypto::KemPublicKey&  leaf_kem_public_key()  const = 0;
    [[nodiscard]] virtual const crypto::KemPrivateKey& leaf_kem_private_key() const = 0;

    /**
     * @brief Rotate the leaf KEM key pair (called by TreeKEM after an update).
     * @return New public key after rotation.
     */
    [[nodiscard]] virtual Result<crypto::KemPublicKey> rotate_leaf_key() = 0;

    // ── Trusted anchors ───────────────────────────────────────────────────────

    [[nodiscard]] virtual const std::vector<Certificate>& trusted_ca_certs() const = 0;
    [[nodiscard]] virtual VoidResult add_trusted_ca(Certificate cert) = 0;
};

/**
 * @brief In-memory credential store — used in tests and when no persistent
 *        storage backend is required (transient embedded deployments).
 */
class InMemoryCredentialStore final : public ICredentialStore {
public:
    /**
     * @brief Construct with pre-generated credentials.
     */
    InMemoryCredentialStore(NodeId             node_id,
                             Certificate        certificate,
                             crypto::DsaPrivateKey ecdsa_sk,
                             crypto::DsaPublicKey  ecdsa_pk,
                             crypto::DsaPrivateKey ml_dsa_sk,
                             crypto::DsaPublicKey  ml_dsa_pk,
                             crypto::KemPublicKey  leaf_kem_pk,
                             crypto::KemPrivateKey leaf_kem_sk,
                             std::vector<Certificate> ca_certs);

    ~InMemoryCredentialStore() override = default;

    [[nodiscard]] NodeId                       our_node_id()          const override;
    [[nodiscard]] const Certificate&           our_certificate()      const override;
    [[nodiscard]] const crypto::DsaPrivateKey& ecdsa_private_key()    const override;
    [[nodiscard]] const crypto::DsaPrivateKey& ml_dsa_private_key()   const override;
    [[nodiscard]] const crypto::DsaPublicKey&  ecdsa_public_key()     const override;
    [[nodiscard]] const crypto::DsaPublicKey&  ml_dsa_public_key()    const override;
    [[nodiscard]] const crypto::KemPublicKey&  leaf_kem_public_key()  const override;
    [[nodiscard]] const crypto::KemPrivateKey& leaf_kem_private_key() const override;
    [[nodiscard]] Result<crypto::KemPublicKey> rotate_leaf_key()       override;
    [[nodiscard]] const std::vector<Certificate>& trusted_ca_certs()  const override;
    [[nodiscard]] VoidResult add_trusted_ca(Certificate cert)          override;

private:
    NodeId                   node_id_;
    Certificate              certificate_;
    crypto::DsaPrivateKey    ecdsa_sk_;
    crypto::DsaPublicKey     ecdsa_pk_;
    crypto::DsaPrivateKey    ml_dsa_sk_;
    crypto::DsaPublicKey     ml_dsa_pk_;
    crypto::KemPublicKey     leaf_kem_pk_;
    crypto::KemPrivateKey    leaf_kem_sk_;
    std::vector<Certificate> ca_certs_;
};

} // namespace uav_pqc::identity
