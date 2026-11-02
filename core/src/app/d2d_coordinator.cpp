// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/d2d_coordinator.hpp"
#include "uav_pqc/common/logging.hpp"

#include <openssl/rand.h>
#include <iostream>

namespace uav_pqc::app {

D2DCoordinator::D2DCoordinator(policy::IAcpe* acpe)
    : acpe_(acpe) {}

Result<std::pair<protocol::D2DSessionRespPayload, protocol::D2DSessionRespPayload>>
D2DCoordinator::coordinate_session_request(const protocol::D2DSessionReqPayload& req,
                                           bool is_initiator_active,
                                           bool is_target_active,
                                           const std::string& target_ip,
                                           std::uint16_t target_port,
                                           const std::string& initiator_ip,
                                           std::uint16_t initiator_port,
                                           const policy::PolicyContext& ctx,
                                           Timestamp now_ms) {
    // 1. Verify both UAVs are active
    if (!is_initiator_active) {
        std::cerr << "[D2D-COORDINATOR] Rejection: Initiator UAV is not authenticated/active." << std::endl;
        return ErrorCode::AuthenticationFailed;
    }
    if (!is_target_active) {
        std::cerr << "[D2D-COORDINATOR] Rejection: Target UAV is not authenticated/active." << std::endl;
        return ErrorCode::AuthenticationFailed;
    }

    // 2. Verify ACPE Policy
    if (acpe_ != nullptr) {
        auto auth_res = acpe_->authorize_d2d_session(req.initiator_node_id, req.target_node_id, ctx);
        if (!auth_res) {
            std::cerr << "[D2D-COORDINATOR] Rejection: ACPE Policy rejected D2D session request." << std::endl;
            return auth_res.error();
        }
    }

    // 3. Generate 16-byte random SessionID
    SessionId sid{};
    if (RAND_bytes(reinterpret_cast<unsigned char*>(sid.data()), 16) != 1) {
        std::cerr << "[D2D-COORDINATOR] Error generating random SessionId." << std::endl;
        return ErrorCode::InternalError;
    }

    // 4. Generate 256-bit (32-byte) random ephemeral session key
    SecureBytes session_key(32);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(session_key.data()), 32) != 1) {
        std::cerr << "[D2D-COORDINATOR] Error generating random 256-bit session key." << std::endl;
        return ErrorCode::InternalError;
    }

    std::uint32_t lifetime = (req.requested_lifetime_seconds > 0) ? req.requested_lifetime_seconds : 300;
    std::uint32_t inactivity_timeout = 60;

    // 5. Store session in GCS active session directory
    session::D2DSession gcs_session;
    gcs_session.session_id = sid;
    gcs_session.local_node_id = req.initiator_node_id;
    gcs_session.peer_node_id = req.target_node_id;
    gcs_session.peer_ip = target_ip;
    gcs_session.peer_port = target_port;
    gcs_session.session_key = SecureBytes(Bytes(session_key.bytes().begin(), session_key.bytes().end()));
    gcs_session.created_at = now_ms;
    gcs_session.expires_at = now_ms + (static_cast<std::uint64_t>(lifetime) * 1000);
    gcs_session.last_active_at = now_ms;
    gcs_session.lifetime_seconds = lifetime;
    gcs_session.inactivity_timeout_seconds = inactivity_timeout;

    manager_.add_session(std::move(gcs_session));

    // 6. Build response payloads (Target info for Initiator, Initiator info for Target)
    protocol::D2DSessionRespPayload resp_to_initiator;
    resp_to_initiator.session_id = sid;
    resp_to_initiator.initiator_node_id = req.initiator_node_id;
    resp_to_initiator.target_node_id = req.target_node_id;
    resp_to_initiator.target_ip = target_ip;
    resp_to_initiator.target_port = target_port;
    resp_to_initiator.session_key = SecureBytes(Bytes(session_key.bytes().begin(), session_key.bytes().end()));
    resp_to_initiator.lifetime_seconds = lifetime;
    resp_to_initiator.inactivity_timeout_seconds = inactivity_timeout;

    protocol::D2DSessionRespPayload resp_to_target;
    resp_to_target.session_id = sid;
    resp_to_target.initiator_node_id = req.initiator_node_id;
    resp_to_target.target_node_id = req.target_node_id;
    resp_to_target.target_ip = initiator_ip;
    resp_to_target.target_port = initiator_port;
    resp_to_target.session_key = SecureBytes(Bytes(session_key.bytes().begin(), session_key.bytes().end()));
    resp_to_target.lifetime_seconds = lifetime;
    resp_to_target.inactivity_timeout_seconds = inactivity_timeout;

    std::cout << "[D2D-COORDINATOR] Successfully authorized D2D session lifetime=" << lifetime << "s." << std::endl;

    return std::make_pair(std::move(resp_to_initiator), std::move(resp_to_target));
}

} // namespace uav_pqc::app
