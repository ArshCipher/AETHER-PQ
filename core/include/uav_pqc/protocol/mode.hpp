// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file mode.hpp
 * @brief Operating mode definitions for the UAV-PQC protocol.
 *
 * The four interoperable modes are selected by the ACPE based on hardware
 * capability, battery level, and mission policy.  They are formally defined
 * in the architecture document and modeled in the Tamarin specification.
 */

#include <cstdint>
#include <string_view>

namespace uav_pqc::protocol {

/**
 * @brief The four interoperable cryptographic operating modes.
 *
 * Encoded as uint8_t to fit in a single protocol byte.
 * Values are fixed and must not be reordered — they appear in protocol
 * messages and will be referenced in the Tamarin model.
 */
enum class OperatingMode : std::uint8_t {
    Classical   = 0x01, ///< X25519 + ECDSA-P256  (legacy-compatible)
    Transition  = 0x02, ///< ML-KEM + ECDSA-P256  (harvest-now-decrypt-later protection)
    Hybrid      = 0x03, ///< ML-KEM+X25519 + ML-DSA+ECDSA-P256 (defense-in-depth)
    PqcOnly     = 0x04, ///< ML-KEM + ML-DSA only  (fully quantum-resistant)
};

/// Returns a human-readable name string for the mode (for logging/config).
[[nodiscard]] constexpr std::string_view to_string(OperatingMode m) noexcept {
    switch (m) {
        case OperatingMode::Classical:  return "Classical";
        case OperatingMode::Transition: return "Transition";
        case OperatingMode::Hybrid:     return "Hybrid";
        case OperatingMode::PqcOnly:    return "PQC-Only";
    }
    return "Unknown";
}

/// Returns true if the mode uses any post-quantum KEM component.
[[nodiscard]] constexpr bool uses_pqc_kem(OperatingMode m) noexcept {
    return m == OperatingMode::Transition ||
           m == OperatingMode::Hybrid     ||
           m == OperatingMode::PqcOnly;
}

/// Returns true if the mode uses any classical key exchange component.
[[nodiscard]] constexpr bool uses_classical_kem(OperatingMode m) noexcept {
    return m == OperatingMode::Classical || m == OperatingMode::Hybrid;
}

/// Returns true if the mode uses any post-quantum authentication.
[[nodiscard]] constexpr bool uses_pqc_dsa(OperatingMode m) noexcept {
    return m == OperatingMode::Hybrid || m == OperatingMode::PqcOnly;
}

/// Returns true if the mode uses classical ECDSA-P256 authentication.
[[nodiscard]] constexpr bool uses_classical_dsa(OperatingMode m) noexcept {
    return m == OperatingMode::Classical ||
           m == OperatingMode::Transition ||
           m == OperatingMode::Hybrid;
}

} // namespace uav_pqc::protocol
