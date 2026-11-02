// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/app/uav.hpp"
#include "uav_pqc/app/ground_control_station.hpp"

#include <vector>
#include <memory>
#include <mutex>

namespace uav_pqc::app {

/**
 * @brief Abstract Swarm interface.
 */
class ISwarm {
public:
    ISwarm() = default;
    virtual ~ISwarm() = default;

    ISwarm(const ISwarm&) = delete;
    ISwarm& operator=(const ISwarm&) = delete;
    ISwarm(ISwarm&&) noexcept = default;
    ISwarm& operator=(ISwarm&&) noexcept = default;

    virtual void add_uav(std::shared_ptr<IUav> uav) = 0;
    virtual void set_gcs(std::shared_ptr<IGroundControlStation> gcs) = 0;
    virtual void tick_swarm(Timestamp now_ms) = 0;
    virtual VoidResult route_packet(const NodeId& dst, ByteSpan packet, Timestamp now_ms) = 0;
    
    virtual const std::vector<std::shared_ptr<IUav>>& get_uavs() const noexcept = 0;
    virtual const std::shared_ptr<IGroundControlStation>& get_gcs() const noexcept = 0;
};

/**
 * @brief Concrete Swarm class managing virtual packet delivery and swarm telemetry coordination.
 */
class Swarm final : public ISwarm {
public:
    Swarm() = default;
    ~Swarm() override = default;

    void add_uav(std::shared_ptr<IUav> uav) override;
    void set_gcs(std::shared_ptr<IGroundControlStation> gcs) override;
    void tick_swarm(Timestamp now_ms) override;
    VoidResult route_packet(const NodeId& dst, ByteSpan packet, Timestamp now_ms) override;

    const std::vector<std::shared_ptr<IUav>>& get_uavs() const noexcept override { return uavs_; }
    const std::shared_ptr<IGroundControlStation>& get_gcs() const noexcept override { return gcs_; }

private:
    std::mutex mutex_;
    std::vector<std::shared_ptr<IUav>> uavs_;
    std::shared_ptr<IGroundControlStation> gcs_;
};

} // namespace uav_pqc::app
