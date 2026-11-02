// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file random.hpp
 * @brief Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) interface.
 *
 * All key generation and nonce creation routes through this interface.
 * Concrete implementations:
 *   Linux/RPi  — getrandom(2) / /dev/urandom
 *   ns-3       — ns3::UniformRandomVariable (deterministic replay)
 *   STM32      — STM32 RNG peripheral via HAL_RNG_GenerateRandomNumber
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <memory>

namespace uav_pqc::platform {

/**
 * @brief Interface for a cryptographically secure RNG.
 */
class ISecureRng {
public:
    ISecureRng()                                   = default;
    ISecureRng(const ISecureRng&)                  = delete;
    ISecureRng& operator=(const ISecureRng&)       = delete;
    ISecureRng(ISecureRng&&) noexcept              = delete;
    ISecureRng& operator=(ISecureRng&&) noexcept   = delete;
    virtual ~ISecureRng()                           = default;

    /**
     * @brief Fill the given buffer with cryptographically secure random bytes.
     *
     * @param out  Destination buffer.  Must not be empty.
     * @return     VoidResult — fails only if the OS entropy source is broken.
     */
    [[nodiscard]] virtual VoidResult fill(MutableByteSpan out) noexcept = 0;

    /**
     * @brief Allocate and fill a Bytes buffer of the given size.
     *
     * @param size  Number of random bytes to generate.
     */
    [[nodiscard]] virtual Result<Bytes> generate(std::size_t size) = 0;

    /**
     * @brief Generate a random 64-bit unsigned integer.
     */
    [[nodiscard]] virtual Result<std::uint64_t> generate_u64() = 0;
};

[[nodiscard]] std::unique_ptr<ISecureRng> make_platform_rng();

} // namespace uav_pqc::platform
