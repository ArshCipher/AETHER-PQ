// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file clock.hpp
 * @brief Platform-independent clock interface.
 *
 * All time-sensitive protocol logic (session expiry, handshake timeouts,
 * rekey timers) queries time through this interface — never through
 * std::chrono::system_clock directly.  This makes the library trivially
 * testable (inject a fake clock) and portable to bare-metal targets that
 * provide a hardware timer via their BSP.
 */

#include "uav_pqc/common/types.hpp"
#include <memory>
#include <chrono>
#include <functional>

namespace uav_pqc::platform {

/**
 * @brief Monotonic clock interface.
 *
 * All return values are in milliseconds since an unspecified but fixed
 * epoch (platform boot, Unix epoch, or simulator start).  The epoch is
 * consistent within a single process lifetime.
 */
class IClock {
public:
    IClock()                               = default;
    IClock(const IClock&)                  = delete;
    IClock& operator=(const IClock&)       = delete;
    IClock(IClock&&) noexcept              = delete;
    IClock& operator=(IClock&&) noexcept   = delete;
    virtual ~IClock()                      = default;

    /**
     * @brief Returns the current time in milliseconds (monotonic).
     *
     * The value is guaranteed to be non-decreasing and free from wall-clock
     * adjustments (NTP steps, DST).  Suitable for computing durations.
     */
    [[nodiscard]] virtual Timestamp now_ms() const noexcept = 0;

    /**
     * @brief Returns the current Unix wall-clock time in milliseconds.
     *
     * Used for certificate validity checks and audit log timestamps.
     * May jump if the system clock is adjusted; do NOT use for duration math.
     */
    [[nodiscard]] virtual Timestamp wall_clock_ms() const noexcept = 0;
};


class SystemClock final : public IClock {
public:
    [[nodiscard]] Timestamp now_ms() const noexcept override {
        auto now = std::chrono::steady_clock::now();
        return static_cast<Timestamp>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()
            ).count()
        );
    }

    [[nodiscard]] Timestamp wall_clock_ms() const noexcept override {
        auto now = std::chrono::system_clock::now();
        return static_cast<Timestamp>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()
            ).count()
        );
    }
};

class SimulationClock final : public IClock {
public:
    SimulationClock() = default;
    explicit SimulationClock(Timestamp initial_time) : current_time_(initial_time) {}
    explicit SimulationClock(std::function<Timestamp()> time_provider) : provider_(std::move(time_provider)) {}

    void advance_ms(Timestamp duration_ms) noexcept {
        current_time_ += duration_ms;
    }

    void set_time_ms(Timestamp time_ms) noexcept {
        current_time_ = time_ms;
    }

    [[nodiscard]] Timestamp now_ms() const noexcept override {
        if (provider_) {
            return provider_();
        }
        return current_time_;
    }

    [[nodiscard]] Timestamp wall_clock_ms() const noexcept override {
        if (provider_) {
            return provider_();
        }
        return current_time_;
    }

private:
    Timestamp current_time_ = 0;
    std::function<Timestamp()> provider_;
};

#ifdef UAV_PQC_ENABLE_NS3
class Ns3Clock final : public IClock {
public:
    [[nodiscard]] Timestamp now_ms() const noexcept override;
    [[nodiscard]] Timestamp wall_clock_ms() const noexcept override;
};
#endif

[[nodiscard]] std::unique_ptr<IClock> make_platform_clock();

} // namespace uav_pqc::platform
