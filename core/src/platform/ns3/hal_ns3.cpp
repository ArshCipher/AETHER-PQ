// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file hal_ns3.cpp
 * @brief ns-3 Simulator Hardware Abstraction Layer orchestration.
 */

#include "uav_pqc/platform/hal.hpp"
#include "uav_pqc/platform/clock.hpp"
#include "uav_pqc/platform/random.hpp"
#include "uav_pqc/common/logging.hpp"

namespace uav_pqc::platform {

class Ns3Hal final : public IHal {
public:
    Ns3Hal() : clock_(make_platform_clock()), rng_(make_platform_rng()) {
        UAV_PQC_LOG_DEBUG("platform", "Ns3Hal initialised");
    }

    [[nodiscard]] IClock& clock() noexcept override { return *clock_; }
    [[nodiscard]] ISecureRng& rng() noexcept override { return *rng_; }

    [[nodiscard]] std::string_view platform_id() const noexcept override {
        return "ns-3 Simulation Platform";
    }

    [[nodiscard]] bool has_hw_aes() const noexcept override {
        return false;
    }

    void submit_async(void (*task)(void*), void* ctx) noexcept override {
        task(ctx);
    }

private:
    std::unique_ptr<IClock>      clock_;
    std::unique_ptr<ISecureRng>  rng_;
};

std::unique_ptr<IHal> make_platform_hal() {
    return std::make_unique<Ns3Hal>();
}

} // namespace uav_pqc::platform
