// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file hal_linux.cpp
 * @brief Linux Hardware Abstraction Layer orchestration.
 */

#include "uav_pqc/platform/hal.hpp"
#include "uav_pqc/platform/clock.hpp"
#include "uav_pqc/platform/random.hpp"
#include "uav_pqc/platform/aes_hw.hpp"
#include "uav_pqc/common/logging.hpp"

namespace uav_pqc::platform {

// The concrete clock and RNG implementations are compiled in separate translation units
// (clock_linux.cpp, random_linux.cpp) and instantiated here using factory functions.

class LinuxHal final : public IHal {
public:
    LinuxHal() : clock_(make_platform_clock()), rng_(make_platform_rng()) {
        UAV_PQC_LOG_DEBUG("platform", "LinuxHal initialised hw_aes={}", has_hw_aes());
    }

    [[nodiscard]] IClock& clock() noexcept override { return *clock_; }
    [[nodiscard]] ISecureRng& rng() noexcept override { return *rng_; }

    [[nodiscard]] std::string_view platform_id() const noexcept override {
#if defined(__APPLE__) && defined(__aarch64__)
        return "macOS/aarch64";
#elif defined(__x86_64__)
        return "Linux/x86_64";
#elif defined(__aarch64__)
        return "Linux/aarch64";
#elif defined(__arm__)
        return "Linux/arm";
#else
        return "Linux/Unknown";
#endif
    }

    [[nodiscard]] bool has_hw_aes() const noexcept override {
        return platform::detect_aes_capability() != platform::AesCapability::None;
    }

    void submit_async(void (*task)(void*), void* ctx) noexcept override {
        // Synchronous fallback for simplicity in the research mock
        task(ctx);
    }

private:
    std::unique_ptr<IClock>      clock_;
    std::unique_ptr<ISecureRng>  rng_;
};

std::unique_ptr<IHal> make_platform_hal() {
    return std::make_unique<LinuxHal>();
}

} // namespace uav_pqc::platform
