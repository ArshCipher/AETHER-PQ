// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file profile.cpp
 * @brief Cryptographic profile factory methods and JSON loading.
 */

#include "uav_pqc/policy/profile.hpp"
#include "uav_pqc/common/logging.hpp"

#include <nlohmann/json.hpp>

namespace uav_pqc::policy {

// ── Factory methods ───────────────────────────────────────────────────────────

ProfileParameters ProfileParameters::lightweight() {
    return ProfileParameters{
        .profile                 = CryptographicProfile::Lightweight,
        .kem_level               = crypto::MlKem::Level::Kem512,
        .dsa_level               = crypto::MlDsa::Level::Dsa44,
        .use_slh_dsa             = false,
        .preferred_aead          = protocol::AeadAlgorithm::ChaCha20Poly,
        .fallback_aead           = protocol::AeadAlgorithm::ChaCha20Poly,
        .hkdf_hash               = crypto::HkdfHash::Sha256,
        .rekey_interval_seconds  = 300,       // 5 minutes
        .max_messages_per_key    = 1ULL << 20, // ~1M messages
        .allow_session_resumption= true,
        .allow_classical_fallback= true,
        .require_hybrid_kem      = false,
    };
}

ProfileParameters ProfileParameters::standard() {
    return ProfileParameters{
        .profile                 = CryptographicProfile::Standard,
        .kem_level               = crypto::MlKem::Level::Kem768,
        .dsa_level               = crypto::MlDsa::Level::Dsa65,
        .use_slh_dsa             = false,
        .preferred_aead          = protocol::AeadAlgorithm::AesGcm256,
        .fallback_aead           = protocol::AeadAlgorithm::ChaCha20Poly,
        .hkdf_hash               = crypto::HkdfHash::Sha256,
        .rekey_interval_seconds  = 600,       // 10 minutes
        .max_messages_per_key    = 1ULL << 24, // ~16M messages
        .allow_session_resumption= true,
        .allow_classical_fallback= false,
        .require_hybrid_kem      = true,
    };
}

ProfileParameters ProfileParameters::hardened() {
    return ProfileParameters{
        .profile                 = CryptographicProfile::Hardened,
        .kem_level               = crypto::MlKem::Level::Kem1024,
        .dsa_level               = crypto::MlDsa::Level::Dsa87,
        .use_slh_dsa             = true,
        .preferred_aead          = protocol::AeadAlgorithm::AesGcm256,
        .fallback_aead           = protocol::AeadAlgorithm::AesGcm256, // no ChaCha fallback in hardened
        .hkdf_hash               = crypto::HkdfHash::Sha512,
        .rekey_interval_seconds  = 120,       // 2 minutes
        .max_messages_per_key    = 1ULL << 20, // conservative
        .allow_session_resumption= false,     // full re-handshake required
        .allow_classical_fallback= false,
        .require_hybrid_kem      = true,
    };
}

// ── from_json ─────────────────────────────────────────────────────────────────

Result<ProfileParameters> ProfileParameters::from_json(ByteSpan json_bytes) {
    try {
        const std::string json_str(
            reinterpret_cast<const char*>(json_bytes.data()), json_bytes.size());
        const auto j = nlohmann::json::parse(json_str);

        const std::string profile_str = j.value("profile", "standard");
        ProfileParameters params;

        if (profile_str == "lightweight") {
            params = lightweight();
        } else if (profile_str == "hardened") {
            params = hardened();
        } else {
            params = standard();
        }

        // Allow selective override of individual fields
        if (j.contains("rekey_interval_seconds")) {
            params.rekey_interval_seconds = j["rekey_interval_seconds"].get<std::uint32_t>();
        }
        if (j.contains("allow_session_resumption")) {
            params.allow_session_resumption = j["allow_session_resumption"].get<bool>();
        }
        if (j.contains("allow_classical_fallback")) {
            params.allow_classical_fallback = j["allow_classical_fallback"].get<bool>();
        }
        if (j.contains("kem_level")) {
            std::string kem_str = j["kem_level"].get<std::string>();
            if (kem_str == "512" || kem_str == "ml-kem-512" || kem_str == "Kem512") {
                params.kem_level = crypto::MlKem::Level::Kem512;
            } else if (kem_str == "768" || kem_str == "ml-kem-768" || kem_str == "Kem768") {
                params.kem_level = crypto::MlKem::Level::Kem768;
            } else if (kem_str == "1024" || kem_str == "ml-kem-1024" || kem_str == "Kem1024") {
                params.kem_level = crypto::MlKem::Level::Kem1024;
            }
        }
        if (j.contains("dsa_level")) {
            std::string dsa_str = j["dsa_level"].get<std::string>();
            if (dsa_str == "44" || dsa_str == "ml-dsa-44" || dsa_str == "Dsa44") {
                params.dsa_level = crypto::MlDsa::Level::Dsa44;
            } else if (dsa_str == "65" || dsa_str == "ml-dsa-65" || dsa_str == "Dsa65") {
                params.dsa_level = crypto::MlDsa::Level::Dsa65;
            } else if (dsa_str == "87" || dsa_str == "ml-dsa-87" || dsa_str == "Dsa87") {
                params.dsa_level = crypto::MlDsa::Level::Dsa87;
            }
        }
        if (j.contains("use_slh_dsa")) {
            params.use_slh_dsa = j["use_slh_dsa"].get<bool>();
        }
        if (j.contains("preferred_aead")) {
            std::string aead_str = j["preferred_aead"].get<std::string>();
            if (aead_str == "aes-gcm-128" || aead_str == "AES-128-GCM" || aead_str == "AesGcm128") {
                params.preferred_aead = protocol::AeadAlgorithm::AesGcm128;
            } else if (aead_str == "aes-gcm-256" || aead_str == "AES-256-GCM" || aead_str == "AesGcm256") {
                params.preferred_aead = protocol::AeadAlgorithm::AesGcm256;
            } else if (aead_str == "chacha20-poly1305" || aead_str == "ChaCha20-Poly1305" || aead_str == "ChaCha20Poly") {
                params.preferred_aead = protocol::AeadAlgorithm::ChaCha20Poly;
            }
        }
        if (j.contains("fallback_aead")) {
            std::string aead_str = j["fallback_aead"].get<std::string>();
            if (aead_str == "aes-gcm-128" || aead_str == "AES-128-GCM" || aead_str == "AesGcm128") {
                params.fallback_aead = protocol::AeadAlgorithm::AesGcm128;
            } else if (aead_str == "aes-gcm-256" || aead_str == "AES-256-GCM" || aead_str == "AesGcm256") {
                params.fallback_aead = protocol::AeadAlgorithm::AesGcm256;
            } else if (aead_str == "chacha20-poly1305" || aead_str == "ChaCha20-Poly1305" || aead_str == "ChaCha20Poly") {
                params.fallback_aead = protocol::AeadAlgorithm::ChaCha20Poly;
            }
        }
        if (j.contains("hkdf_hash")) {
            std::string hash_str = j["hkdf_hash"].get<std::string>();
            if (hash_str == "sha-256" || hash_str == "SHA-256" || hash_str == "Sha256" || hash_str == "sha256") {
                params.hkdf_hash = crypto::HkdfHash::Sha256;
            } else if (hash_str == "sha-384" || hash_str == "SHA-384" || hash_str == "Sha384" || hash_str == "sha384") {
                params.hkdf_hash = crypto::HkdfHash::Sha384;
            } else if (hash_str == "sha-512" || hash_str == "SHA-512" || hash_str == "Sha512" || hash_str == "sha512") {
                params.hkdf_hash = crypto::HkdfHash::Sha512;
            }
        }
        if (j.contains("max_messages_per_key")) {
            params.max_messages_per_key = j["max_messages_per_key"].get<std::uint64_t>();
        }
        if (j.contains("require_hybrid_kem")) {
            params.require_hybrid_kem = j["require_hybrid_kem"].get<bool>();
        }

        return ok<ProfileParameters>(std::move(params));
    } catch (const std::exception& e) {
        return err<ProfileParameters>(ErrorCode::InvalidArgument,
            std::string("ProfileParameters::from_json failed: ") + e.what());
    }
}

} // namespace uav_pqc::policy
