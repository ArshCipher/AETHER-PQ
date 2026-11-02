// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/app/event_bus.hpp"
#include "uav_pqc/app/configuration_manager.hpp"
#include "uav_pqc/app/crypto_manager.hpp"
#include "uav_pqc/app/network_manager.hpp"
#include "uav_pqc/app/session_manager.hpp"
#include "uav_pqc/app/acpe_engine.hpp"
#include "uav_pqc/app/treekem_controller.hpp"
#include "uav_pqc/protocol/handshake.hpp"
#include "uav_pqc/app/mavlink.hpp"

#include <memory>
#include <string>
#include <unordered_map>

#include "uav_pqc/app/d2d_coordinator.hpp"

namespace uav_pqc::app {

/**
 * @brief Abstract GroundControlStation interface.
 */
class IGroundControlStation {
public:
    IGroundControlStation() = default;
    virtual ~IGroundControlStation() = default;

    IGroundControlStation(const IGroundControlStation&) = delete;
    IGroundControlStation& operator=(const IGroundControlStation&) = delete;
    IGroundControlStation(IGroundControlStation&&) noexcept = default;
    IGroundControlStation& operator=(IGroundControlStation&&) noexcept = default;

    virtual VoidResult initialize(const std::string& config_str) = 0;
    virtual VoidResult handle_incoming_uav_packet(const NodeId& uav_id, ByteSpan packet, Timestamp now_ms) = 0;
    virtual Result<group::GroupKeyUpdate> enroll_uav(const NodeId& uav_id, const crypto::KemPublicKey& uav_leaf_pk) = 0;
    virtual Result<group::GroupKeyUpdate> revoke_uav(const NodeId& uav_id) = 0;
    virtual VoidResult broadcast_policy_update(const policy::AcpeDecision& decision) = 0;
    virtual VoidResult send_mavlink_command(const NodeId& uav_id, const mavlink::CommandLong& cmd, Timestamp now_ms = 0) = 0;
    virtual std::vector<NodeId> get_active_uavs() const = 0;

    virtual const NodeId& get_node_id() const noexcept = 0;
    virtual const std::shared_ptr<ITreeKemController>& get_treekem_controller() const noexcept = 0;
};

/**
 * @brief Concrete GroundControlStation class orchestrating high-security post-quantum swarm control.
 */
class GroundControlStation final : public IGroundControlStation {
public:
    struct NodeIdHash {
        std::size_t operator()(const NodeId& id) const noexcept {
            std::size_t hash = 0;
            for (auto b : id) {
                hash = (hash * 31) + static_cast<std::size_t>(b);
            }
            return hash;
        }
    };

    GroundControlStation(std::shared_ptr<IEventBus> event_bus,
                         std::shared_ptr<IConfigurationManager> config_mgr,
                         std::shared_ptr<ICryptoManager> crypto_mgr,
                         std::shared_ptr<INetworkManager> network_mgr,
                         std::shared_ptr<ISessionManager> session_mgr,
                         std::shared_ptr<IAcpeEngine> acpe_engine,
                         std::shared_ptr<ITreeKemController> treekem_ctrl);
    ~GroundControlStation() override = default;

    VoidResult initialize(const std::string& config_str) override;
    VoidResult handle_incoming_uav_packet(const NodeId& uav_id, ByteSpan packet, Timestamp now_ms) override;
    Result<group::GroupKeyUpdate> enroll_uav(const NodeId& uav_id, const crypto::KemPublicKey& uav_leaf_pk) override;
    Result<group::GroupKeyUpdate> revoke_uav(const NodeId& uav_id) override;
    VoidResult broadcast_policy_update(const policy::AcpeDecision& decision) override;
    VoidResult send_mavlink_command(const NodeId& uav_id, const mavlink::CommandLong& cmd, Timestamp now_ms = 0) override;
    std::vector<NodeId> get_active_uavs() const override;

    const NodeId& get_node_id() const noexcept override { return node_id_; }
    const std::shared_ptr<ITreeKemController>& get_treekem_controller() const noexcept override { return treekem_ctrl_; }
    void set_certificate(Bytes cert) { cert_ = std::move(cert); }

    const std::shared_ptr<INetworkManager>& get_network_manager() const noexcept { return network_mgr_; }
    const std::shared_ptr<ISessionManager>& get_session_manager() const noexcept { return session_mgr_; }
    const std::unordered_map<NodeId, SessionId, NodeIdHash>& get_active_uav_sessions() const noexcept { return active_uav_sessions_; }

    D2DCoordinator& get_d2d_coordinator() noexcept { return d2d_coordinator_; }
    const D2DCoordinator& get_d2d_coordinator() const noexcept { return d2d_coordinator_; }

private:
    Bytes cert_;
    std::shared_ptr<IEventBus> event_bus_;
    std::shared_ptr<IConfigurationManager> config_mgr_;
    std::shared_ptr<ICryptoManager> crypto_mgr_;
    std::shared_ptr<INetworkManager> network_mgr_;
    std::shared_ptr<ISessionManager> session_mgr_;
    std::shared_ptr<IAcpeEngine> acpe_engine_;
    std::shared_ptr<ITreeKemController> treekem_ctrl_;
    D2DCoordinator d2d_coordinator_;

    NodeId node_id_;
    // Map of active/ongoing handshakes by peer UAV NodeId
    std::unordered_map<NodeId, std::unique_ptr<protocol::IHandshake>, NodeIdHash> handshakes_;
    std::unordered_map<NodeId, SessionId, NodeIdHash> active_uav_sessions_;
    mavlink::MavlinkParser mavlink_parser_;

    void handle_reassembled_uav_message(const NodeId& uav_id, const Bytes& msg);
};

} // namespace uav_pqc::app
