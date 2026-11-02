// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/swarm.hpp"

namespace uav_pqc::app {

void Swarm::add_uav(std::shared_ptr<IUav> uav) {
    std::lock_guard<std::mutex> lock(mutex_);
    uavs_.push_back(std::move(uav));
}

void Swarm::set_gcs(std::shared_ptr<IGroundControlStation> gcs) {
    std::lock_guard<std::mutex> lock(mutex_);
    gcs_ = std::move(gcs);
}

void Swarm::tick_swarm(Timestamp) {
    // Tick simulation/routing parameters here if applicable
}

VoidResult Swarm::route_packet(const NodeId& dst, ByteSpan packet, Timestamp now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Route to GCS if destination matches GCS
    if (gcs_ && gcs_->get_node_id() == dst) {
        // Map GCS receiver to default mock sender (zero NodeId or extract from packet)
        NodeId mock_sender{};
        return gcs_->handle_incoming_uav_packet(mock_sender, packet, now_ms);
    }
    
    // Route to the corresponding UAV
    for (auto& uav : uavs_) {
        if (uav->get_node_id() == dst) {
            return uav->receive_packet(packet, now_ms);
        }
    }
    
    return err(ErrorCode::SessionNotFound, "Route destination node not found in swarm");
}

} // namespace uav_pqc::app
