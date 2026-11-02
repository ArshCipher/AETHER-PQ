// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file aes_hw.hpp
 * @brief Runtime detection of hardware AES acceleration.
 *
 * The ACPE and AEAD selector use this to decide whether to prefer AES-GCM
 * (hardware path) or ChaCha20-Poly1305 (software path) on the current node.
 *
 * Detection is done once at startup and cached.  All functions are reentrant
 * and thread-safe after the first call.
 */

#include <cstdint>

namespace uav_pqc::platform {

/**
 * @brief Detected hardware AES capability flags.
 *
 * Multiple flags may be set simultaneously (e.g. a server with AES-NI
 * and VAES extensions will have both kAesNi and kVaes set).
 */
enum class AesCapability : std::uint32_t {
    None        = 0x00u, ///< No hardware AES support detected
    AesNi       = 0x01u, ///< Intel/AMD AES-NI (x86_64)
    ArmCrypto   = 0x02u, ///< ARMv8 Cryptography Extensions (aarch64 / Cortex-A)
    ArmV7Crypto = 0x04u, ///< ARMv7 NEON crypto (Cortex-A7/A53 on RPi 2/3)
    Vaes        = 0x08u, ///< Intel VAES (AVX-512F + AES-NI extension)
};

[[nodiscard]] inline AesCapability operator|(AesCapability a, AesCapability b) noexcept {
    return static_cast<AesCapability>(
        static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}
[[nodiscard]] inline bool has_capability(AesCapability flags, AesCapability cap) noexcept {
    return (static_cast<std::uint32_t>(flags) & static_cast<std::uint32_t>(cap)) != 0u;
}

/**
 * @brief Detect and cache hardware AES capabilities for this CPU.
 *
 * Calls CPUID (x86_64) or reads /proc/cpuinfo or hwcap (ARM).  Safe to call
 * multiple times — result is computed once and stored in a local static.
 *
 * @return Bitmask of AesCapability flags.
 */
[[nodiscard]] AesCapability detect_aes_capability() noexcept;

/**
 * @brief Returns true if ANY hardware AES acceleration is available.
 *
 * Convenience wrapper over detect_aes_capability().
 */
[[nodiscard]] inline bool has_hw_aes() noexcept {
    return detect_aes_capability() != AesCapability::None;
}

} // namespace uav_pqc::platform
