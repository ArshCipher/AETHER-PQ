// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file ml_dsa.cpp
 * @brief ML-DSA (FIPS 204) implementation via liboqs.
 */

#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <oqs/sig.h>

#include <stdexcept>

namespace uav_pqc::crypto {

// ── Custom deleter ────────────────────────────────────────────────────────────

void MlDsa::OqsSigDeleter::operator()(OQS_SIG* p) const noexcept {
    OQS_SIG_free(p);
}

// ── OQS method name mapping ───────────────────────────────────────────────────

std::string_view MlDsa::oqs_method_name(Level level) noexcept {
    switch (level) {
        case Level::Dsa44: return OQS_SIG_alg_ml_dsa_44;
        case Level::Dsa65: return OQS_SIG_alg_ml_dsa_65;
        case Level::Dsa87: return OQS_SIG_alg_ml_dsa_87;
    }
    return OQS_SIG_alg_ml_dsa_65;
}

// ── Constructor ───────────────────────────────────────────────────────────────

MlDsa::MlDsa(Level level) : level_(level) {
    const std::string_view method = oqs_method_name(level);
    sig_.reset(OQS_SIG_new(method.data()));
    if (!sig_) {
        throw std::runtime_error(
            std::string("[uav_pqc] MlDsa: OQS_SIG_new failed for method '")
            + std::string(method) + "'. "
            "Ensure liboqs was built with ML-DSA support (-DOQS_ENABLE_SIG_ML_DSA=ON).");
    }
    UAV_PQC_LOG_DEBUG("crypto.ml_dsa", "Initialised ML-DSA level={} method={}",
                      static_cast<int>(level), method);
}

MlDsa::~MlDsa() = default;
MlDsa::MlDsa(MlDsa&&) noexcept = default;
MlDsa& MlDsa::operator=(MlDsa&&) noexcept = default;

// ── Metadata ──────────────────────────────────────────────────────────────────

std::string_view MlDsa::algorithm_id()       const noexcept { return sig_->method_name; }
std::size_t      MlDsa::public_key_size()    const noexcept { return sig_->length_public_key; }
std::size_t      MlDsa::private_key_size()   const noexcept { return sig_->length_secret_key; }
std::size_t      MlDsa::max_signature_size() const noexcept { return sig_->length_signature; }

// ── generate_keypair ──────────────────────────────────────────────────────────

Result<DsaKeyPair> MlDsa::generate_keypair() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::MlDsa);
    DsaKeyPair kp;
    kp.public_key.data.resize(sig_->length_public_key);
    kp.private_key.data.resize(sig_->length_secret_key);

    const OQS_STATUS status = OQS_SIG_keypair(
        sig_.get(),
        reinterpret_cast<uint8_t*>(kp.public_key.data.data()),
        reinterpret_cast<uint8_t*>(kp.private_key.data.data())
    );

    if (status != OQS_SUCCESS) {
        UAV_PQC_LOG_ERROR("crypto.ml_dsa", "OQS_SIG_keypair failed");
        return err<DsaKeyPair>(ErrorCode::KeyGenerationFailed,
                               "ML-DSA keypair generation failed");
    }

    UAV_PQC_LOG_TRACE("crypto.ml_dsa", "generate_keypair: pk_size={} sk_size={}",
                      kp.public_key.size(), kp.private_key.size());
    return ok<DsaKeyPair>(std::move(kp));
}

// ── sign ──────────────────────────────────────────────────────────────────────

Result<Signature> MlDsa::sign(const DsaPrivateKey& sk, ByteSpan message) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::MlDsa);
    if (sk.data.size() != sig_->length_secret_key) {
        return err<Signature>(ErrorCode::InvalidArgument,
                              "ML-DSA sign: private key has incorrect size");
    }

    Signature signature;
    signature.data.resize(sig_->length_signature);
    std::size_t sig_len = sig_->length_signature;

    const OQS_STATUS status = OQS_SIG_sign(
        sig_.get(),
        reinterpret_cast<uint8_t*>(signature.data.data()),
        &sig_len,
        reinterpret_cast<const uint8_t*>(message.data()),
        message.size(),
        reinterpret_cast<const uint8_t*>(sk.data.data())
    );

    if (status != OQS_SUCCESS) {
        UAV_PQC_LOG_ERROR("crypto.ml_dsa", "OQS_SIG_sign failed");
        return err<Signature>(ErrorCode::SigningFailed, "ML-DSA signing failed");
    }

    // Trim to actual signature length (may be shorter than max for some schemes)
    signature.data.resize(sig_len);
    UAV_PQC_LOG_TRACE("crypto.ml_dsa", "sign: msg_size={} sig_size={}",
                      message.size(), sig_len);
    return ok<Signature>(std::move(signature));
}

// ── verify ────────────────────────────────────────────────────────────────────

Result<bool> MlDsa::verify(const DsaPublicKey& pk, ByteSpan message,
                            const Signature& signature) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::MlDsa);
    if (pk.data.size() != sig_->length_public_key) {
        return err<bool>(ErrorCode::InvalidArgument,
                         "ML-DSA verify: public key has incorrect size");
    }

    const OQS_STATUS status = OQS_SIG_verify(
        sig_.get(),
        reinterpret_cast<const uint8_t*>(message.data()),
        message.size(),
        reinterpret_cast<const uint8_t*>(signature.data.data()),
        signature.data.size(),
        reinterpret_cast<const uint8_t*>(pk.data.data())
    );

    if (status == OQS_SUCCESS) {
        UAV_PQC_LOG_TRACE("crypto.ml_dsa", "verify: OK msg_size={}", message.size());
        return ok<bool>(true);
    }

    UAV_PQC_LOG_WARN("crypto.ml_dsa", "verify: FAILED msg_size={} sig_size={}",
                     message.size(), signature.data.size());
    return err<bool>(ErrorCode::VerificationFailed, "ML-DSA signature verification failed");
}

} // namespace uav_pqc::crypto
