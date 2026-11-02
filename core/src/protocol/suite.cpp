// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file suite.cpp
 * @brief CipherSuite factory methods and utility functions.
 */

#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/common/logging.hpp"

#include <sstream>

namespace uav_pqc::protocol {

// ── Factory methods ───────────────────────────────────────────────────────────

CipherSuite CipherSuite::make_classical(AeadAlgorithm aead) {
    return CipherSuite{
        .mode                 = OperatingMode::Classical,
        .kem_level            = crypto::MlKem::Level::Kem512,  // not used in classical
        .dsa_level            = crypto::MlDsa::Level::Dsa44,   // not used in classical
        .aead_algorithm       = aead,
        .hkdf_hash            = crypto::HkdfHash::Sha256,
        .max_session_seconds  = 3600,        // 1 hour
        .max_messages_per_key = 1ULL << 24,
    };
}

CipherSuite CipherSuite::make_transition(crypto::MlKem::Level kem, AeadAlgorithm aead) {
    return CipherSuite{
        .mode                 = OperatingMode::Transition,
        .kem_level            = kem,
        .dsa_level            = crypto::MlDsa::Level::Dsa44,   // not used
        .aead_algorithm       = aead,
        .hkdf_hash            = crypto::HkdfHash::Sha256,
        .max_session_seconds  = 600,
        .max_messages_per_key = 1ULL << 20,
    };
}

CipherSuite CipherSuite::make_hybrid(AeadAlgorithm aead) {
    return CipherSuite{
        .mode                 = OperatingMode::Hybrid,
        .kem_level            = crypto::MlKem::Level::Kem768,
        .dsa_level            = crypto::MlDsa::Level::Dsa65,
        .aead_algorithm       = aead,
        .hkdf_hash            = crypto::HkdfHash::Sha256,
        .max_session_seconds  = 600,
        .max_messages_per_key = 1ULL << 24,
    };
}

CipherSuite CipherSuite::make_pqc_only(crypto::MlKem::Level kem,
                                        crypto::MlDsa::Level dsa,
                                        AeadAlgorithm aead) {
    return CipherSuite{
        .mode                 = OperatingMode::PqcOnly,
        .kem_level            = kem,
        .dsa_level            = dsa,
        .aead_algorithm       = aead,
        .hkdf_hash            = crypto::HkdfHash::Sha512,
        .max_session_seconds  = 120,
        .max_messages_per_key = 1ULL << 20,
    };
}

// ── Utility ───────────────────────────────────────────────────────────────────

std::size_t CipherSuite::aead_key_size() const noexcept {
    switch (aead_algorithm) {
        case AeadAlgorithm::AesGcm128:    return 16;
        case AeadAlgorithm::AesGcm256:    return 32;
        case AeadAlgorithm::ChaCha20Poly: return 32;
    }
    return 32;
}

std::string CipherSuite::to_string() const {
    std::ostringstream ss;
    ss << protocol::to_string(mode)
       << "+ML-KEM-" << (kem_level == crypto::MlKem::Level::Kem512 ? "512" :
                          kem_level == crypto::MlKem::Level::Kem768 ? "768" : "1024")
       << "+" << ::uav_pqc::protocol::to_string(aead_algorithm);
    return ss.str();
}

} // namespace uav_pqc::protocol
