// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file trust_chain.hpp
 * @brief Certificate chain validation against a set of trusted CA anchors.
 *
 * The TrustChain validator:
 *  1. Parses the certificate chain (leaf → intermediate → root)
 *  2. Verifies each issuer signature up the chain
 *  3. Checks that the chain terminates at a trusted CA anchor
 *  4. Verifies all validity windows against the current time
 *  5. Rejects revoked certificates (checked against a local CRL or OCSP stub)
 *
 * Authentication is ALWAYS completed before session key establishment begins
 * (per architecture invariant) to prevent unauthenticated KEM operations.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/identity/certificate.hpp"
#include "uav_pqc/crypto/dsa.hpp"

#include "uav_pqc/platform/clock.hpp"

namespace uav_pqc::identity {

/**
 * @brief Validated chain result returned by TrustChain::validate().
 */
struct ValidationResult {
    Certificate              leaf;              ///< Validated leaf certificate
    std::vector<Certificate> chain;             ///< Full chain (leaf → root)
    bool                     is_pqc_signed;     ///< Leaf has valid ML-DSA signature
    bool                     is_ecdsa_signed;   ///< Leaf has valid ECDSA-P256 signature
};

/**
 * @brief Certificate chain validator.
 *
 * Constructed with a set of trusted CA anchor certificates.  Thread-safe
 * after construction (all state is immutable).
 */
class TrustChain {
public:
    /**
     * @brief Construct with trusted CA anchor certificates.
     *
     * @param ca_anchors  CA certificates that are unconditionally trusted.
     *                    At least one anchor is required.
     */
    explicit TrustChain(std::vector<Certificate> ca_anchors, std::shared_ptr<platform::IClock> clock = nullptr);
    ~TrustChain() = default;

    TrustChain(const TrustChain&)            = default;
    TrustChain& operator=(const TrustChain&) = default;
    TrustChain(TrustChain&&) noexcept        = default;
    TrustChain& operator=(TrustChain&&) noexcept = default;

    // ── Validation ────────────────────────────────────────────────────────────

    /**
     * @brief Validate a DER-encoded certificate chain.
     *
     * @param chain_der  Concatenated DER certificates (leaf-first).
     * @param now_ms     Current time for validity window checks.
     * @return           ValidationResult, or an appropriate error code.
     */
    [[nodiscard]] Result<ValidationResult>
    validate(const std::vector<Bytes>& chain_der, Timestamp now_ms = 0) const;

    /**
     * @brief Validate a pre-parsed certificate chain.
     */
    [[nodiscard]] Result<ValidationResult>
    validate(const std::vector<Certificate>& chain, Timestamp now_ms = 0) const;

    // ── Revocation (stub — full CRL/OCSP is future work) ─────────────────────

    /**
     * @brief Add a revoked NodeId to the local block list.
     *
     * Certificates whose subject NodeId appears here are rejected immediately.
     */
    void revoke(const NodeId& node_id);

    [[nodiscard]] bool is_revoked(const NodeId& node_id) const noexcept;

    // ── Anchor management ─────────────────────────────────────────────────────

    [[nodiscard]] const std::vector<Certificate>& anchors() const noexcept { return anchors_; }

    void add_anchor(Certificate cert);

private:
    std::vector<Certificate> anchors_;
    std::vector<NodeId>      revoked_ids_;
    std::shared_ptr<platform::IClock> clock_;

    [[nodiscard]] VoidResult verify_signature_pair(
        const Certificate& subject,
        const Certificate& issuer) const;
};

} // namespace uav_pqc::identity
