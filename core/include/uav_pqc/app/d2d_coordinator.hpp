// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file d2d_coordinator.hpp
 * @brief GCS D2D Session Coordination Service.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/protocol/d2d_messages.hpp"
#include "uav_pqc/session/d2d_manager.hpp"
#include "uav_pqc/policy/acpe.hpp"

#include <memory>
#include <string>

namespace uav_pqc::app {

/**
 * @brief D2D Session Coordination Service running inside the Ground Control Station (GCS).
 *
 * Verifies UAV authentication, active transport connection, certificate validity,
 * and ACPE policy authorization before issuing 256-bit ephemeral D2D session keys.
 */
class D2DCoordinator {
public:
    explicit D2DCoordinator(policy::IAcpe* acpe = nullptr);
    ~D2DCoordinator() = default;

    D2DCoordinator(const D2DCoordinator&) = delete;
    D2DCoordinator& operator=(const D2DCoordinator&) = delete;

    void set_acpe_engine(policy::IAcpe* acpe) noexcept { acpe_ = acpe; }

    /**
     * @brief Process an incoming D2DSessionReq from UAV-A.
     *
     * @param req                     Received session request payload.
     * @param is_initiator_active    True if UAV-A is authenticated and active.
     * @param is_target_active       True if UAV-B is authenticated and active.
     * @param target_ip               IP address of target UAV-B.
     * @param target_port             Port of target UAV-B.
     * @param initiator_ip            IP address of requesting UAV-A.
     * @param initiator_port          Port of requesting UAV-A.
     * @param ctx                     Current runtime policy context.
     * @param now_ms                  Current timestamp in milliseconds.
     * @return                        Pair of D2DSessionRespPayload for UAV-A and UAV-B on success, or ErrorCode.
     */
    Result<std::pair<protocol::D2DSessionRespPayload, protocol::D2DSessionRespPayload>>
    coordinate_session_request(const protocol::D2DSessionReqPayload& req,
                               bool is_initiator_active,
                               bool is_target_active,
                               const std::string& target_ip,
                               std::uint16_t target_port,
                               const std::string& initiator_ip,
                               std::uint16_t initiator_port,
                               const policy::PolicyContext& ctx,
                               Timestamp now_ms);

    /**
     * @brief Access the GCS D2D active session manager.
     */
    session::D2DSessionManager& get_manager() noexcept { return manager_; }
    const session::D2DSessionManager& get_manager() const noexcept { return manager_; }

private:
    policy::IAcpe* acpe_ = nullptr;
    session::D2DSessionManager manager_;
};

} // namespace uav_pqc::app
