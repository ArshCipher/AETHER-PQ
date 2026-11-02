// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file hal.hpp
 * @brief Platform Hardware Abstraction Layer (HAL) interface.
 *
 * The HAL decouples the library core from the underlying operating system and
 * hardware.  A concrete implementation is selected at link time by the CMake
 * platform target:
 *
 *   - src/platform/linux/     — standard POSIX Linux (and Raspberry Pi OS)
 *   - src/platform/ns3/       — ns-3 simulation (time/random via ns3::Simulator)
 *   - src/platform/stm32/     — bare-metal STM32 HAL (future)
 *
 * Every concrete HAL must inherit from IHal and implement all pure virtuals.
 * A shared_ptr<IHal> is injected into modules that need platform services,
 * enabling clean substitution during unit tests.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/platform/clock.hpp"
#include "uav_pqc/platform/random.hpp"

#include <cstddef>
#include <memory>
#include <string_view>

namespace uav_pqc::platform {

/**
 * @brief Root HAL interface — aggregates clock and RNG sub-services.
 *
 * Concrete implementations are created via the factory function
 * make_platform_hal() declared at the bottom of this header and defined in
 * each platform's source directory.
 */
class IHal {
public:
    IHal()                           = default;
    IHal(const IHal&)                = delete;
    IHal& operator=(const IHal&)     = delete;
    IHal(IHal&&) noexcept            = delete;
    IHal& operator=(IHal&&) noexcept = delete;
    virtual ~IHal()                  = default;

    // ── Sub-service accessors ─────────────────────────────────────────────────

    /// Returns a reference to the platform clock implementation.
    [[nodiscard]] virtual IClock& clock() noexcept = 0;

    /// Returns a reference to the cryptographically secure RNG.
    [[nodiscard]] virtual ISecureRng& rng() noexcept = 0;

    // ── Platform metadata ─────────────────────────────────────────────────────

    /// Human-readable platform identifier (e.g. "Linux/x86_64", "RaspberryPi/aarch64").
    [[nodiscard]] virtual std::string_view platform_id() const noexcept = 0;

    /// Returns true if the platform has hardware AES acceleration (e.g. AES-NI, ARMv8 Crypto).
    [[nodiscard]] virtual bool has_hw_aes() const noexcept = 0;

    // ── Optional async work queue ─────────────────────────────────────────────

    /**
     * @brief Submit a callable to run on a background execution context.
     *
     * On Linux/RPi this may dispatch to a thread pool.  On bare-metal targets
     * this executes synchronously in the caller's thread.  The callable must
     * be noexcept to prevent termination of the flight-critical main loop.
     */
    virtual void submit_async(void (*task)(void* ctx), void* ctx) noexcept = 0;
};

// ── Factory function (defined per platform in src/platform/<platform>/) ────────

/**
 * @brief Create the appropriate IHal implementation for the current platform.
 *
 * Called once at startup by the top-level application.  The returned pointer
 * is passed down to all modules that require platform services.
 *
 * @return A heap-allocated, owning IHal instance, or nullptr on failure.
 */
[[nodiscard]] std::unique_ptr<IHal> make_platform_hal();

} // namespace uav_pqc::platform
