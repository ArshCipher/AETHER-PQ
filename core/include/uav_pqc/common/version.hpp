// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file version.hpp
 * @brief Compile-time and runtime version information for uav_pqc.
 */

#include <cstdint>
#include <string_view>

namespace uav_pqc {

// ── Compile-time version constants ────────────────────────────────────────────

inline constexpr std::uint16_t kVersionMajor = 0;
inline constexpr std::uint16_t kVersionMinor = 1;
inline constexpr std::uint16_t kVersionPatch = 0;

/// Full version as a monotonically increasing integer: major*10000+minor*100+patch.
inline constexpr std::uint32_t kVersionNumeric =
    static_cast<std::uint32_t>(kVersionMajor) * 10000u +
    static_cast<std::uint32_t>(kVersionMinor) * 100u +
    static_cast<std::uint32_t>(kVersionPatch);

/// Full version as a compile-time string literal "MAJOR.MINOR.PATCH".
inline constexpr std::string_view kVersionString = "0.1.0";

/// Project name string.
inline constexpr std::string_view kProjectName = "uav_pqc";

/// Brief description.
inline constexpr std::string_view kProjectDescription =
    "Post-Quantum Communication Architecture for Heterogeneous UAV Networks";

// ── NIST standard references ───────────────────────────────────────────────────

/// ML-KEM standard reference (FIPS 203).
inline constexpr std::string_view kMlKemStandard = "FIPS 203 (ML-KEM)";

/// ML-DSA standard reference (FIPS 204).
inline constexpr std::string_view kMlDsaStandard = "FIPS 204 (ML-DSA)";

/// SLH-DSA standard reference (FIPS 205, offline use only).
inline constexpr std::string_view kSlhDsaStandard = "FIPS 205 (SLH-DSA)";

} // namespace uav_pqc
