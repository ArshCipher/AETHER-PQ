// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file profile.hpp
 * @brief Cryptographic profile definitions and parameter sets.
 *
 * Profiles map mission/hardware context to specific algorithm instantiations.
 * Three profiles are defined; SLH-DSA is restricted to offline/Hardened use.
 *
 * Profile parameters are immutable value types; the ACPE selects the active
 * profile and produces a CipherSuite from it.
 */

#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/protocol/suite.hpp"

#include <cstdint>
#include <string_view>

namespace uav_pqc::policy {

/**
 * @brief The three cryptographic profiles.
 *
 * Values are stable (appear in JSON config and Tamarin model).
 */
enum class CryptographicProfile : std::uint8_t {
    Lightweight = 0x01, ///< Battery-constrained small UAVs
    Standard    = 0x02, ///< General mission-critical UAVs (default)
    Hardened    = 0x03, ///< Military / high-value ISR missions
};

[[nodiscard]] constexpr std::string_view to_string(CryptographicProfile p) noexcept {
    switch (p) {
        case CryptographicProfile::Lightweight: return "Lightweight";
        case CryptographicProfile::Standard:    return "Standard";
        case CryptographicProfile::Hardened:    return "Hardened";
    }
    return "Unknown";
}

/**
 * @brief Complete parameter set for a cryptographic profile.
 *
 * Encodes the algorithm choices, rekey frequency, and legacy support flags
 * for a single profile.  Instances are created via the factory below.
 */
struct ProfileParameters {
    CryptographicProfile    profile;

    // KEM selection
    crypto::MlKem::Level    kem_level;              ///< ML-KEM-512/768/1024

    // DSA selection
    crypto::MlDsa::Level    dsa_level;              ///< ML-DSA-44/65/87
    bool                    use_slh_dsa;            ///< SLH-DSA for audit logs (Hardened only)

    // AEAD preferences (order = priority)
    protocol::AeadAlgorithm preferred_aead;         ///< Primary cipher
    protocol::AeadAlgorithm fallback_aead;          ///< If hw acceleration unavailable

    // HKDF
    crypto::HkdfHash        hkdf_hash;              ///< SHA-256/384/512

    // Rekey policy
    std::uint32_t           rekey_interval_seconds; ///< Max session age before rekey
    std::uint64_t           max_messages_per_key;   ///< Max AEAD messages per session key
    bool                    allow_session_resumption;

    // Legacy interoperability
    bool                    allow_classical_fallback;  ///< Classical mode fallback permitted
    bool                    require_hybrid_kem;        ///< Must use hybrid KEM if PQC capable

    // ── Factory methods ────────────────────────────────────────────────────────

    /// Default parameters for Lightweight profile (ML-KEM-512 / ML-DSA-44 / ChaCha20).
    [[nodiscard]] static ProfileParameters lightweight();

    /// Default parameters for Standard profile (ML-KEM-768 / ML-DSA-65 / AES-256-GCM).
    [[nodiscard]] static ProfileParameters standard();

    /// Default parameters for Hardened profile (ML-KEM-1024 / ML-DSA-87 / AES-256-GCM).
    [[nodiscard]] static ProfileParameters hardened();

    /// Load parameters from a JSON configuration object (nlohmann::json).
    /// Declared here; implemented in policy/profile.cpp to avoid header deps on json.
    [[nodiscard]] static Result<ProfileParameters> from_json(ByteSpan json_bytes);

#if defined(__cpp_impl_three_way_comparison) || (defined(__cplusplus) && __cplusplus >= 202002L)
    bool operator==(const ProfileParameters&) const noexcept = default;
#else
    bool operator==(const ProfileParameters& o) const noexcept {
        return profile == o.profile &&
               kem_level == o.kem_level &&
               dsa_level == o.dsa_level &&
               use_slh_dsa == o.use_slh_dsa &&
               preferred_aead == o.preferred_aead &&
               fallback_aead == o.fallback_aead &&
               hkdf_hash == o.hkdf_hash &&
               rekey_interval_seconds == o.rekey_interval_seconds &&
               max_messages_per_key == o.max_messages_per_key &&
               allow_session_resumption == o.allow_session_resumption &&
               allow_classical_fallback == o.allow_classical_fallback &&
               require_hybrid_kem == o.require_hybrid_kem;
    }
#endif
};

} // namespace uav_pqc::policy
