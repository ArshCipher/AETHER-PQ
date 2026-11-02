// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file ml_kem.cpp
 * @brief ML-KEM (FIPS 203) implementation via liboqs.
 */

#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <oqs/kem.h>

#include <cassert>
#include <stdexcept>

namespace uav_pqc::crypto {

// ── Custom deleter ────────────────────────────────────────────────────────────

void MlKem::OqsKemDeleter::operator()(OQS_KEM* p) const noexcept {
    OQS_KEM_free(p);
}

// ── OQS method name mapping ───────────────────────────────────────────────────

std::string_view MlKem::oqs_method_name(Level level) noexcept {
    switch (level) {
        case Level::Kem512:  return OQS_KEM_alg_ml_kem_512;
        case Level::Kem768:  return OQS_KEM_alg_ml_kem_768;
        case Level::Kem1024: return OQS_KEM_alg_ml_kem_1024;
    }
    return OQS_KEM_alg_ml_kem_768;
}

// ── Constructor ───────────────────────────────────────────────────────────────

MlKem::MlKem(Level level) : level_(level) {
    const std::string_view method = oqs_method_name(level);
    kem_.reset(OQS_KEM_new(method.data()));
    if (!kem_) {
        throw std::runtime_error(
            std::string("[uav_pqc] MlKem: OQS_KEM_new failed for method '")
            + std::string(method) + "'. "
            "Ensure liboqs was built with ML-KEM support (-DOQS_ENABLE_KEM_ML_KEM=ON).");
    }
    UAV_PQC_LOG_DEBUG("crypto.ml_kem", "Initialised ML-KEM level={} method={}",
                      static_cast<int>(level), method);
}

MlKem::~MlKem() = default;
MlKem::MlKem(MlKem&&) noexcept = default;
MlKem& MlKem::operator=(MlKem&&) noexcept = default;

// ── Metadata ──────────────────────────────────────────────────────────────────

std::string_view MlKem::algorithm_id()       const noexcept { return kem_->method_name; }
std::size_t      MlKem::public_key_size()    const noexcept { return kem_->length_public_key; }
std::size_t      MlKem::private_key_size()   const noexcept { return kem_->length_secret_key; }
std::size_t      MlKem::ciphertext_size()    const noexcept { return kem_->length_ciphertext; }
std::size_t      MlKem::shared_secret_size() const noexcept { return kem_->length_shared_secret; }

// ── generate_keypair ──────────────────────────────────────────────────────────

Result<KemKeyPair> MlKem::generate_keypair() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::MlKem);
    KemKeyPair kp;
    kp.public_key.data.resize(kem_->length_public_key);
    kp.private_key.data.resize(kem_->length_secret_key);

    const OQS_STATUS status = OQS_KEM_keypair(
        kem_.get(),
        reinterpret_cast<uint8_t*>(kp.public_key.data.data()),
        reinterpret_cast<uint8_t*>(kp.private_key.data.data())
    );

    if (status != OQS_SUCCESS) {
        UAV_PQC_LOG_ERROR("crypto.ml_kem", "OQS_KEM_keypair failed");
        return err<KemKeyPair>(ErrorCode::KeyGenerationFailed,
                               "ML-KEM keypair generation failed (OQS_KEM_keypair)");
    }

    UAV_PQC_LOG_TRACE("crypto.ml_kem", "generate_keypair: pk_size={} sk_size={}",
                      kp.public_key.size(), kp.private_key.size());
    return ok<KemKeyPair>(std::move(kp));
}

// ── encapsulate ───────────────────────────────────────────────────────────────

Result<EncapsulationResult> MlKem::encapsulate(const KemPublicKey& pk) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::MlKem);
    if (pk.data.size() != kem_->length_public_key) {
        return err<EncapsulationResult>(ErrorCode::InvalidArgument,
            "ML-KEM encapsulate: public key has incorrect size");
    }

    EncapsulationResult result;
    result.ciphertext.data.resize(kem_->length_ciphertext);
    result.shared_secret.data.resize(kem_->length_shared_secret);

    const OQS_STATUS status = OQS_KEM_encaps(
        kem_.get(),
        reinterpret_cast<uint8_t*>(result.ciphertext.data.data()),
        reinterpret_cast<uint8_t*>(result.shared_secret.data.data()),
        reinterpret_cast<const uint8_t*>(pk.data.data())
    );

    if (status != OQS_SUCCESS) {
        UAV_PQC_LOG_ERROR("crypto.ml_kem", "OQS_KEM_encaps failed");
        return err<EncapsulationResult>(ErrorCode::EncapsulationFailed,
                                        "ML-KEM encapsulation failed (OQS_KEM_encaps)");
    }

    UAV_PQC_LOG_TRACE("crypto.ml_kem", "encapsulate: ct_size={} ss_size={}",
                      result.ciphertext.size(), result.shared_secret.size());
    return ok<EncapsulationResult>(std::move(result));
}

// ── decapsulate ───────────────────────────────────────────────────────────────

Result<SharedSecret> MlKem::decapsulate(const KemPrivateKey& sk,
                                         const KemCiphertext& ct) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::MlKem);
    if (sk.data.size() != kem_->length_secret_key) {
        return err<SharedSecret>(ErrorCode::InvalidArgument,
            "ML-KEM decapsulate: private key has incorrect size");
    }
    if (ct.data.size() != kem_->length_ciphertext) {
        return err<SharedSecret>(ErrorCode::InvalidArgument,
            "ML-KEM decapsulate: ciphertext has incorrect size");
    }

    SharedSecret ss;
    ss.data.resize(kem_->length_shared_secret);

    const OQS_STATUS status = OQS_KEM_decaps(
        kem_.get(),
        reinterpret_cast<uint8_t*>(ss.data.data()),
        reinterpret_cast<const uint8_t*>(ct.data.data()),
        reinterpret_cast<const uint8_t*>(sk.data.data())
    );

    // ML-KEM is IND-CCA2 secure: decapsulation always succeeds (returns
    // a pseudorandom value for invalid ciphertexts).  However liboqs may
    // return OQS_ERROR for internal allocation failures.
    if (status != OQS_SUCCESS) {
        UAV_PQC_LOG_ERROR("crypto.ml_kem", "OQS_KEM_decaps failed (internal error)");
        return err<SharedSecret>(ErrorCode::DecapsulationFailed,
                                  "ML-KEM decapsulation failed (OQS_KEM_decaps)");
    }

    UAV_PQC_LOG_TRACE("crypto.ml_kem", "decapsulate: ss_size={}", ss.size());
    return ok<SharedSecret>(std::move(ss));
}

Result<KemKeyPair> MlKem::generate_keypair_deterministic(ByteSpan seed) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::MlKem);
    Hkdf hkdf(HkdfHash::Sha256);
    auto expanded_seed_r = hkdf.derive(
        {},
        seed,
        bytes_from_sv("ml-kem keypair seed"),
        kem_->length_keypair_seed
    );
    if (!expanded_seed_r) {
        return err<KemKeyPair>(expanded_seed_r.error());
    }
    const auto& expanded_seed = expanded_seed_r.value();

    KemKeyPair kp;
    kp.public_key.data.resize(kem_->length_public_key);
    kp.private_key.data.resize(kem_->length_secret_key);

    const OQS_STATUS status = OQS_KEM_keypair_derand(
        kem_.get(),
        reinterpret_cast<uint8_t*>(kp.public_key.data.data()),
        reinterpret_cast<uint8_t*>(kp.private_key.data.data()),
        reinterpret_cast<const uint8_t*>(expanded_seed.data())
    );

    if (status != OQS_SUCCESS) {
        UAV_PQC_LOG_ERROR("crypto.ml_kem", "OQS_KEM_keypair_derand failed");
        return err<KemKeyPair>(ErrorCode::KeyGenerationFailed,
                               "ML-KEM deterministic keypair generation failed");
    }

    return ok<KemKeyPair>(std::move(kp));
}

} // namespace uav_pqc::crypto
