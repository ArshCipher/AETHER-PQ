// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/identity/certificate.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/common/types.hpp"

#include <mutex>
#include <string>
#include <vector>
#include <optional>

namespace uav_pqc::app {

/**
 * @brief Abstract CertificateAuthority interface.
 */
class ICertificateAuthority {
public:
    ICertificateAuthority() = default;
    virtual ~ICertificateAuthority() = default;

    ICertificateAuthority(const ICertificateAuthority&) = delete;
    ICertificateAuthority& operator=(const ICertificateAuthority&) = delete;
    ICertificateAuthority(ICertificateAuthority&&) noexcept = default;
    ICertificateAuthority& operator=(ICertificateAuthority&&) noexcept = default;

    virtual Result<identity::Certificate> issue_certificate(
        const std::string& subject_name,
        const NodeId& subject_id,
        const crypto::DsaPublicKey& ecdsa_pub,
        const crypto::DsaPublicKey& mldsa_pub,
        Timestamp lifetime_ms,
        Timestamp now_ms) = 0;

    virtual Result<identity::Certificate> generate_root_certificate(
        const std::string& subject_name,
        Timestamp lifetime_ms,
        Timestamp now_ms) = 0;

    virtual Result<identity::Certificate> renew_certificate(
        const identity::Certificate& old_cert,
        Timestamp new_lifetime_ms,
        Timestamp now_ms) = 0;

    virtual VoidResult revoke_certificate(
        const NodeId& node_id,
        Timestamp revocation_time,
        std::uint8_t reason) = 0;

    virtual Result<Bytes> generate_crl(Timestamp now_ms) const = 0;
    virtual VoidResult import_crl(ByteSpan crl_bytes) = 0;

    virtual std::vector<identity::Certificate> get_issued_certificates() const = 0;
    virtual std::vector<NodeId> get_revoked_node_ids() const = 0;

    virtual VoidResult save_to_file(const std::string& filepath) const = 0;
    virtual VoidResult load_from_file(const std::string& filepath) = 0;
        
    virtual const NodeId& get_ca_node_id() const noexcept = 0;
    virtual const std::optional<identity::Certificate>& get_ca_certificate() const noexcept = 0;
    virtual Result<Bytes> sign_data(ByteSpan data) const = 0;
};

/**
 * @brief Concrete CertificateAuthority implementing the complete PKI and database management.
 */
class CertificateAuthority final : public ICertificateAuthority {
public:
    struct RevocationEntry {
        NodeId node_id;
        Timestamp revocation_time;
        std::uint8_t reason;
    };

    CertificateAuthority() = default;
    CertificateAuthority(NodeId ca_node_id, crypto::DsaKeyPair ca_keypair);
    ~CertificateAuthority() override = default;

    Result<identity::Certificate> issue_certificate(
        const std::string& subject_name,
        const NodeId& subject_id,
        const crypto::DsaPublicKey& ecdsa_pub,
        const crypto::DsaPublicKey& mldsa_pub,
        Timestamp lifetime_ms,
        Timestamp now_ms) override;

    Result<identity::Certificate> generate_root_certificate(
        const std::string& subject_name,
        Timestamp lifetime_ms,
        Timestamp now_ms) override;

    Result<identity::Certificate> renew_certificate(
        const identity::Certificate& old_cert,
        Timestamp new_lifetime_ms,
        Timestamp now_ms) override;

    VoidResult revoke_certificate(
        const NodeId& node_id,
        Timestamp revocation_time,
        std::uint8_t reason) override;

    Result<Bytes> generate_crl(Timestamp now_ms) const override;
    VoidResult import_crl(ByteSpan crl_bytes) override;

    std::vector<identity::Certificate> get_issued_certificates() const override;
    std::vector<NodeId> get_revoked_node_ids() const override;

    VoidResult save_to_file(const std::string& filepath) const override;
    VoidResult load_from_file(const std::string& filepath) override;

    const NodeId& get_ca_node_id() const noexcept override { return ca_node_id_; }
    const std::optional<identity::Certificate>& get_ca_certificate() const noexcept override { return ca_cert_; }
    Result<Bytes> sign_data(ByteSpan data) const override;

private:
    mutable std::mutex mutex_;
    NodeId ca_node_id_{};
    crypto::DsaKeyPair ca_keypair_;
    std::optional<identity::Certificate> ca_cert_;
    std::vector<identity::Certificate> issued_db_;
    std::vector<RevocationEntry> revocation_db_;
};

} // namespace uav_pqc::app
