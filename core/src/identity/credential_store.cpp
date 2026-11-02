// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file credential_store.cpp
 * @brief InMemoryCredentialStore implementation.
 */

#include "uav_pqc/identity/credential_store.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/common/logging.hpp"

namespace uav_pqc::identity {

InMemoryCredentialStore::InMemoryCredentialStore(
    NodeId                   node_id,
    Certificate              certificate,
    crypto::DsaPrivateKey    ecdsa_sk,
    crypto::DsaPublicKey     ecdsa_pk,
    crypto::DsaPrivateKey    ml_dsa_sk,
    crypto::DsaPublicKey     ml_dsa_pk,
    crypto::KemPublicKey     leaf_kem_pk,
    crypto::KemPrivateKey    leaf_kem_sk,
    std::vector<Certificate> ca_certs)
    : node_id_(std::move(node_id)),
      certificate_(std::move(certificate)),
      ecdsa_sk_(std::move(ecdsa_sk)),
      ecdsa_pk_(std::move(ecdsa_pk)),
      ml_dsa_sk_(std::move(ml_dsa_sk)),
      ml_dsa_pk_(std::move(ml_dsa_pk)),
      leaf_kem_pk_(std::move(leaf_kem_pk)),
      leaf_kem_sk_(std::move(leaf_kem_sk)),
      ca_certs_(std::move(ca_certs)) {}

NodeId InMemoryCredentialStore::our_node_id() const { return node_id_; }

const Certificate& InMemoryCredentialStore::our_certificate() const {
    return certificate_;
}

const crypto::DsaPrivateKey& InMemoryCredentialStore::ecdsa_private_key() const {
    return ecdsa_sk_;
}

const crypto::DsaPrivateKey& InMemoryCredentialStore::ml_dsa_private_key() const {
    return ml_dsa_sk_;
}

const crypto::DsaPublicKey& InMemoryCredentialStore::ecdsa_public_key() const {
    return ecdsa_pk_;
}

const crypto::DsaPublicKey& InMemoryCredentialStore::ml_dsa_public_key() const {
    return ml_dsa_pk_;
}

const crypto::KemPublicKey& InMemoryCredentialStore::leaf_kem_public_key() const {
    return leaf_kem_pk_;
}

const crypto::KemPrivateKey& InMemoryCredentialStore::leaf_kem_private_key() const {
    return leaf_kem_sk_;
}

Result<crypto::KemPublicKey> InMemoryCredentialStore::rotate_leaf_key() {
    crypto::MlKem kem(crypto::MlKem::Level::Kem768);
    auto kp_r = kem.generate_keypair();
    if (!kp_r) return err<crypto::KemPublicKey>(kp_r.error());

    leaf_kem_pk_ = std::move(kp_r.value().public_key);
    leaf_kem_sk_ = std::move(kp_r.value().private_key);

    UAV_PQC_LOG_INFO("identity.credential_store", "Leaf KEM key rotated");
    return ok<crypto::KemPublicKey>(leaf_kem_pk_);
}

const std::vector<Certificate>& InMemoryCredentialStore::trusted_ca_certs() const {
    return ca_certs_;
}

VoidResult InMemoryCredentialStore::add_trusted_ca(Certificate cert) {
    ca_certs_.push_back(std::move(cert));
    return ok();
}

} // namespace uav_pqc::identity
