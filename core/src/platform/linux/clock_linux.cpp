// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file clock_linux.cpp
 * @brief Linux Clock implementation using clock_gettime.
 */

#include "uav_pqc/platform/clock.hpp"
#include <time.h>

namespace uav_pqc::platform {

std::unique_ptr<IClock> make_platform_clock() {
    return std::make_unique<SystemClock>();
}

} // namespace uav_pqc::platform
