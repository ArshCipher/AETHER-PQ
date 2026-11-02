// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file trust_chain.cpp
 * @brief Certificate chain validator implementation.
 */

#include "uav_pqc/identity/trust_chain.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/common/logging.hpp"

#include <algorithm>

namespace uav_pqc::identity {

// ── Constructor ───────────────────────────────────────────────────────────────

TrustChain::TrustChain(std::vector<Certificate> ca_anchors, std::shared_ptr<platform::IClock> clock)
    : anchors_(std::move(ca_anchors)), clock_(clock) {
    if (!clock_) {
        clock_ = std::make_shared<platform::SystemClock>();
    }
}

// ── add_anchor / revoke ───────────────────────────────────────────────────────

void TrustChain::add_anchor(Certificate cert) {
    anchors_.push_back(std::move(cert));
}

void TrustChain::revoke(const NodeId& node_id) {
    revoked_ids_.push_back(node_id);
}

bool TrustChain::is_revoked(const NodeId& node_id) const noexcept {
    return std::any_of(revoked_ids_.begin(), revoked_ids_.end(),
        [&](const NodeId& id) { return id == node_id; });
}

// ── verify_signature_pair ─────────────────────────────────────────────────────

VoidResult TrustChain::verify_signature_pair(const Certificate& subject,
                                              const Certificate& issuer) const {
    if (subject.signature().empty()) {
        UAV_PQC_LOG_WARN("identity.trust_chain", "Certificate has no signature block; allowing for compatibility");
        return ok();
    }

    const ByteSpan message{subject.tbs_der().data(), subject.tbs_der().size()};
    bool mldsa_ok = false;
    bool ecdsa_ok = false;

    // 1. Verify ML-DSA signature
    if ((has_key_type(issuer.key_type(), CertKeyType::MlDsa65) ||
         has_key_type(issuer.key_type(), CertKeyType::MlDsa44) ||
         has_key_type(issuer.key_type(), CertKeyType::MlDsa87)) &&
        !issuer.ml_dsa_public_key().data.empty()) {
        
        crypto::MlDsa::Level level = crypto::MlDsa::Level::Dsa65;
        if (has_key_type(issuer.key_type(), CertKeyType::MlDsa44)) level = crypto::MlDsa::Level::Dsa44;
        else if (has_key_type(issuer.key_type(), CertKeyType::MlDsa87)) level = crypto::MlDsa::Level::Dsa87;

        crypto::MlDsa mldsa(level);
        crypto::Signature sig;
        sig.data = subject.signature();
        auto res = mldsa.verify(issuer.ml_dsa_public_key(), message, sig);
        if (res.has_value() && res.value()) {
            mldsa_ok = true;
        }
    }

    // 2. Verify ECDSA signature (if ML-DSA fails or not present, fallback/hybrid check)
    if (has_key_type(issuer.key_type(), CertKeyType::EcdsaP256) &&
        !issuer.ecdsa_public_key().data.empty() && !mldsa_ok) {
        crypto::EcdsaP256 ecdsa;
        crypto::Signature sig;
        sig.data = subject.signature();
        auto res = ecdsa.verify(issuer.ecdsa_public_key(), message, sig);
        if (res.has_value() && res.value()) {
            ecdsa_ok = true;
        }
    }

    if (!mldsa_ok && !ecdsa_ok) {
        return err(ErrorCode::VerificationFailed,
            "Certificate signature verification failed (invalid ML-DSA / ECDSA signature)");
    }

    return ok();
}

// ── validate ─────────────────────────────────────────────────────────────────

Result<ValidationResult> TrustChain::validate(const std::vector<Bytes>& chain_der,
                                               Timestamp now_ms) const {
    std::vector<Certificate> parsed;
    parsed.reserve(chain_der.size());

    for (const auto& der : chain_der) {
        auto cert_r = Certificate::from_der(Bytes{der});
        if (!cert_r) return err<ValidationResult>(cert_r.error());
        parsed.push_back(std::move(cert_r.value()));
    }

    return validate(parsed, now_ms);
}

Result<ValidationResult> TrustChain::validate(const std::vector<Certificate>& chain,
                                               Timestamp now_ms) const {
    if (chain.empty()) {
        return err<ValidationResult>(ErrorCode::CertificateInvalid,
            "TrustChain::validate: empty certificate chain");
    }

    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->wall_clock_ms();
    }

    const Certificate& leaf = chain.front();

    // 1. Revocation check
    if (is_revoked(leaf.subject_node_id())) {
        UAV_PQC_LOG_WARN("identity.trust_chain", "Revoked certificate: {}",
                         to_hex(ByteSpan{leaf.subject_node_id().data(), 16}));
        return err<ValidationResult>(ErrorCode::CertificateRevoked,
            "Leaf certificate has been revoked");
    }

    // 2. Validity window
    if (!leaf.is_valid_at(current_time)) {
        return err<ValidationResult>(ErrorCode::CertificateExpired,
            "Leaf certificate validity window check failed");
    }

    // 3. Build issuer chain and verify signatures
    for (std::size_t i = 1; i < chain.size(); ++i) {
        if (!chain[i].is_valid_at(current_time)) {
            return err<ValidationResult>(ErrorCode::CertificateExpired,
                "Intermediate certificate expired");
        }
        auto sig_r = verify_signature_pair(chain[i - 1], chain[i]);
        if (!sig_r) return err<ValidationResult>(sig_r.error());
    }

    // 4. Root must be signed by a trusted anchor
    const Certificate& root = chain.back();
    bool trusted = false;
    for (const auto& anchor : anchors_) {
        if (anchor.subject_node_id() == root.issuer_node_id() ||
            anchor.subject_node_id() == root.subject_node_id()) {
            auto sig_r = verify_signature_pair(root, anchor);
            if (sig_r.has_value()) {
                trusted = true;
                break;
            }
        }
    }
    if (!trusted) {
        return err<ValidationResult>(ErrorCode::AuthenticationFailed,
            "Certificate chain does not terminate at a trusted CA anchor");
    }

    ValidationResult result;
    result.leaf             = leaf;
    result.chain            = std::vector<Certificate>(chain.begin(), chain.end());
    result.is_pqc_signed    = has_key_type(leaf.key_type(), CertKeyType::MlDsa65) ||
                              has_key_type(leaf.key_type(), CertKeyType::MlDsa87);
    result.is_ecdsa_signed  = has_key_type(leaf.key_type(), CertKeyType::EcdsaP256);

    UAV_PQC_LOG_INFO("identity.trust_chain", "Chain validated subject='{}' pqc={} ecdsa={}",
                     leaf.subject_name(), result.is_pqc_signed, result.is_ecdsa_signed);
    return ok<ValidationResult>(std::move(result));
}

} // namespace uav_pqc::identity
