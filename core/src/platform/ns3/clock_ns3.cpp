// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file clock_ns3.cpp
 * @brief ns-3 Simulator Clock implementation using ns3::Simulator.
 */

#include "uav_pqc/platform/clock.hpp"
#include <ns3/simulator.h>

namespace uav_pqc::platform {

Timestamp Ns3Clock::now_ms() const noexcept {
    return static_cast<Timestamp>(ns3::Simulator::Now().GetMilliSeconds());
}

Timestamp Ns3Clock::wall_clock_ms() const noexcept {
    return static_cast<Timestamp>(ns3::Simulator::Now().GetMilliSeconds());
}

std::unique_ptr<IClock> make_platform_clock() {
    return std::make_unique<Ns3Clock>();
}

} // namespace uav_pqc::platform
