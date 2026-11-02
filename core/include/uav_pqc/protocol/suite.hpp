// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file suite.hpp
 * @brief CipherSuite — the complete algorithm selection for a protocol session.
 *
 * A CipherSuite is the concrete instantiation of an OperatingMode + Profile:
 * it specifies exactly which KEM level, DSA level, AEAD algorithm, HKDF hash,
 * and rekey interval apply to a session.  The ACPE produces a CipherSuite
 * from the negotiated mode and profile; the handshake and session layers
 * consume it.
 *
 * CipherSuites are immutable value types: copy and compare freely.
 */

#include "uav_pqc/protocol/mode.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/crypto/hkdf.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace uav_pqc::protocol {

/**
 * @brief AEAD algorithm selector (independent of key length).
 */
enum class AeadAlgorithm : std::uint8_t {
    AesGcm128      = 0x01, ///< AES-128-GCM
    AesGcm256      = 0x02, ///< AES-256-GCM
    ChaCha20Poly   = 0x03, ///< ChaCha20-Poly1305
};

[[nodiscard]] constexpr std::string_view to_string(AeadAlgorithm a) noexcept {
    switch (a) {
        case AeadAlgorithm::AesGcm128:    return "AES-128-GCM";
        case AeadAlgorithm::AesGcm256:    return "AES-256-GCM";
        case AeadAlgorithm::ChaCha20Poly: return "ChaCha20-Poly1305";
    }
    return "Unknown";
}

/**
 * @brief Complete algorithm suite for a single protocol session.
 *
 * Produced by ACPE::select_suite() and passed into HandshakeContext,
 * Session, and GroupKeyManager.
 */
struct CipherSuite {
    OperatingMode       mode;            ///< Classical / Transition / Hybrid / PQC-Only
    crypto::MlKem::Level kem_level;     ///< ML-KEM parameter set (512/768/1024)
    crypto::MlDsa::Level dsa_level;     ///< ML-DSA parameter set (44/65/87)
    AeadAlgorithm       aead_algorithm; ///< Symmetric cipher
    crypto::HkdfHash    hkdf_hash;      ///< Underlying hash for HKDF

    /// Maximum session lifetime in seconds before forced rekey.
    std::uint32_t max_session_seconds;

    /// Maximum number of AEAD messages before nonce rotation triggers a rekey.
    std::uint64_t max_messages_per_key;

    // ── Factory helpers for each mode × profile combination ──────────────────

    /// Classical mode suite (always uses AES-128-GCM or ChaCha20 by hw capability).
    static CipherSuite make_classical(AeadAlgorithm aead);

    /// Transition mode: ML-KEM-512/768 + ECDSA-P256.
    static CipherSuite make_transition(crypto::MlKem::Level kem, AeadAlgorithm aead);

    /// Hybrid mode: ML-KEM-768 + X25519 / ML-DSA-65 + ECDSA-P256.
    static CipherSuite make_hybrid(AeadAlgorithm aead);

    /// PQC-Only mode suite at a given ML-KEM/ML-DSA security level.
    static CipherSuite make_pqc_only(crypto::MlKem::Level kem,
                                     crypto::MlDsa::Level dsa,
                                     AeadAlgorithm        aead);

    // ── Utility ───────────────────────────────────────────────────────────────

    /// Returns the AEAD key length in bytes implied by the algorithm.
    [[nodiscard]] std::size_t aead_key_size() const noexcept;

    /// Returns a human-readable summary for logging and configuration output.
    [[nodiscard]] std::string to_string() const;

    /// Returns true if this suite provides post-quantum key establishment.
    [[nodiscard]] bool is_quantum_resistant() const noexcept {
        return uses_pqc_kem(mode);
    }

#if defined(__cpp_impl_three_way_comparison) || (defined(__cplusplus) && __cplusplus >= 202002L)
    bool operator==(const CipherSuite&) const noexcept = default;
#else
    bool operator==(const CipherSuite& o) const noexcept {
        return mode == o.mode &&
               kem_level == o.kem_level &&
               dsa_level == o.dsa_level &&
               aead_algorithm == o.aead_algorithm &&
               hkdf_hash == o.hkdf_hash &&
               max_session_seconds == o.max_session_seconds &&
               max_messages_per_key == o.max_messages_per_key;
    }
#endif
};

} // namespace uav_pqc::protocol
