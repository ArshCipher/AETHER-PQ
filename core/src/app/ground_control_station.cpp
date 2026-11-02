// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/ground_control_station.hpp"
#include <iostream>

namespace uav_pqc::app {

GroundControlStation::GroundControlStation(std::shared_ptr<IEventBus> event_bus,
                                           std::shared_ptr<IConfigurationManager> config_mgr,
                                           std::shared_ptr<ICryptoManager> crypto_mgr,
                                           std::shared_ptr<INetworkManager> network_mgr,
                                           std::shared_ptr<ISessionManager> session_mgr,
                                           std::shared_ptr<IAcpeEngine> acpe_engine,
                                           std::shared_ptr<ITreeKemController> treekem_ctrl)
    : event_bus_(std::move(event_bus)),
      config_mgr_(std::move(config_mgr)),
      crypto_mgr_(std::move(crypto_mgr)),
      network_mgr_(std::move(network_mgr)),
      session_mgr_(std::move(session_mgr)),
      acpe_engine_(std::move(acpe_engine)),
      treekem_ctrl_(std::move(treekem_ctrl)) {
    
    network_mgr_->set_message_handler([this](const NodeId& sender, const Bytes& msg) {
        this->handle_reassembled_uav_message(sender, msg);
    });
}

VoidResult GroundControlStation::initialize(const std::string& config_str) {
    auto cfg_r = config_mgr_->load_from_string(config_str);
    if (!cfg_r) return err(cfg_r.error());

    node_id_ = cfg_r.value().our_node_id;

    // Inject runtime-configured profile parameters into ACPE engine
    if (acpe_engine_) {
        if (auto* core = acpe_engine_->get_core_engine()) {
            core->set_lightweight_profile(cfg_r.value().lightweight_profile);
            core->set_standard_profile(cfg_r.value().standard_profile);
            core->set_hardened_profile(cfg_r.value().hardened_profile);
        }
    }

    // Load static DSA credentials if not already set
    if (!crypto_mgr_->get_static_dsa_keypair()) {
        auto dsa_r = crypto_mgr_->generate_dsa_keypair();
        if (dsa_r) {
            crypto_mgr_->set_static_dsa_keypair(std::move(dsa_r.value()));
        }
    }

    return ok();
}

VoidResult GroundControlStation::handle_incoming_uav_packet(const NodeId& uav_id, ByteSpan packet, Timestamp now_ms) {
    // Before passing to network manager, map or inject sender context if necessary.
    // For standard D2D packet flow:
    return network_mgr_->handle_incoming_packet(packet, now_ms);
}

Result<group::GroupKeyUpdate> GroundControlStation::enroll_uav(const NodeId& uav_id, const crypto::KemPublicKey& uav_leaf_pk) {
    group::SwarmMember member{
        .node_id = uav_id,
        .leaf_key = uav_leaf_pk,
        .leaf_index = 0,
        .joined_at_ms = 0
    };
    return treekem_ctrl_->register_member(member);
}

Result<group::GroupKeyUpdate> GroundControlStation::revoke_uav(const NodeId& uav_id) {
    return treekem_ctrl_->revoke_member(uav_id, group::RekeyReason::MemberLeft);
}

VoidResult GroundControlStation::broadcast_policy_update(const policy::AcpeDecision& decision) {
    // Custom policy broadcast frame
    Bytes body;
    body.push_back(static_cast<std::byte>(decision.mode));
    body.push_back(static_cast<std::byte>(decision.profile));
    
    Bytes payload = body;
    std::uint8_t msg_type = 0;
    if (session_mgr_->get_group_key()) {
        auto enc_r = session_mgr_->encrypt_group_broadcast(body, ByteSpan{}, 0);
        if (enc_r) {
            payload = std::move(enc_r.value());
            msg_type = 2; // message_type=2 signifies group key encrypted
        } else {
            std::cerr << "[GCS] Error: Group encryption for policy broadcast failed: " << enc_r.error().message << std::endl;
        }
    }

    auto res = network_mgr_->send_message(protocol::wrap_packet(protocol::ProtocolID::COMMAND, payload, msg_type));
    if (res) {
        event_bus_->publish(std::string("Policy broadcast successful"));
    }
    return res;
}

VoidResult GroundControlStation::send_mavlink_command(const NodeId& uav_id, const mavlink::CommandLong& cmd, Timestamp now_ms) {
    auto frame = mavlink::MavlinkFrame::pack(cmd, 0, static_cast<uint8_t>(node_id_[0]), static_cast<uint8_t>(node_id_[1]));
    std::vector<uint8_t> frame_bytes = frame.serialize();

    // Publish raw decrypted stream for loopback sniffing
    event_bus_->publish(DecryptedMavlinkStream{Bytes(reinterpret_cast<const std::byte*>(frame_bytes.data()), 
                                                     reinterpret_cast<const std::byte*>(frame_bytes.data()) + frame_bytes.size())});

    // Check if it's a swarm broadcast (uav_id is all zeros)
    if (uav_id == NodeId{}) {
        Bytes payload;
        std::uint8_t msg_type = 0;
        if (session_mgr_->get_group_key()) {
            auto enc_r = session_mgr_->encrypt_group_broadcast(ByteSpan{reinterpret_cast<const std::byte*>(frame_bytes.data()), frame_bytes.size()}, ByteSpan{}, 0);
            if (enc_r) {
                payload = std::move(enc_r.value());
                msg_type = 2; // message_type=2 signifies group key encrypted
            } else {
                return err(enc_r.error());
            }
        } else {
            payload = Bytes(reinterpret_cast<const std::byte*>(frame_bytes.data()), reinterpret_cast<const std::byte*>(frame_bytes.data()) + frame_bytes.size());
        }

        std::cout << "[MAVLINK GCS] Broadcasting COMMAND_LONG to entire swarm: command=" << cmd.command << std::endl;
        return network_mgr_->send_message(protocol::wrap_packet(protocol::ProtocolID::COMMAND, payload, msg_type));
    }

    auto it = active_uav_sessions_.find(uav_id);
    if (it == active_uav_sessions_.end()) {
        return err(Error(ErrorCode::SessionNotFound, "No active session for UAV"));
    }
    auto sess_r = session_mgr_->get_session(it->second, uav_id, now_ms);
    if (!sess_r) {
        return err(Error(ErrorCode::SessionNotFound, "Session not found in manager"));
    }

    auto enc_r = sess_r.value()->encrypt(ByteSpan{reinterpret_cast<const std::byte*>(frame_bytes.data()), frame_bytes.size()}, ByteSpan{});
    if (!enc_r) return err(enc_r.error());

    std::cout << "[MAVLINK GCS] Sending COMMAND_LONG: command=" << cmd.command 
              << " to UAV: " << static_cast<int>(uav_id[0]) << ":" << static_cast<int>(uav_id[1]) << std::endl;

    return network_mgr_->send_message_to(uav_id, protocol::wrap_packet(protocol::ProtocolID::COMMAND, enc_r.value(), 1, it->second));
}

void GroundControlStation::handle_reassembled_uav_message(const NodeId& uav_id, const Bytes& msg) {
    auto uhdr_r = protocol::UniversalHeader::deserialise(msg);
    if (!uhdr_r) {
        std::cerr << "[GCS] Error deserialising universal header: " << uhdr_r.error().message << std::endl;
        return;
    }

    const auto& uhdr = uhdr_r.value();
    
    if (msg.size() < protocol::UniversalHeader::kWireSize + uhdr.payload_length) {
        std::cerr << "[GCS] Error: Truncated universal packet body" << std::endl;
        return;
    }
    
    Bytes payload(msg.begin() + protocol::UniversalHeader::kWireSize,
                  msg.begin() + protocol::UniversalHeader::kWireSize + uhdr.payload_length);

    switch (uhdr.protocol_id) {
        case protocol::ProtocolID::HANDSHAKE: {
            auto hdr_r = protocol::MessageHeader::deserialise(payload);
            if (hdr_r && hdr_r.value().type == protocol::MessageType::ClientHello) {
                handshakes_.erase(uav_id);
            }
            auto& hs = handshakes_[uav_id];
            if (!hs) {
                if (hdr_r && hdr_r.value().type == protocol::MessageType::ClientHello) {
                    protocol::HandshakeConfig hcfg;
                    hcfg.our_node_id = node_id_;
                    hcfg.offered_modes = config_mgr_->get_config().offered_modes;
                    if (!cert_.empty()) {
                        hcfg.our_certificate = cert_;
                    } else {
                        hcfg.our_certificate = {std::byte{0x03}, std::byte{0x04}};
                    } 
                    const auto& static_kp = crypto_mgr_->get_static_dsa_keypair();
                    if (static_kp) {
                        hcfg.our_dsa_private_key.data.resize(static_kp->private_key.size());
                        std::copy(static_kp->private_key.span().begin(), static_kp->private_key.span().end(),
                                  hcfg.our_dsa_private_key.data.data());

                        hcfg.our_ml_dsa_private_key.data.resize(static_kp->private_key.size());
                        std::copy(static_kp->private_key.span().begin(), static_kp->private_key.span().end(),
                                  hcfg.our_ml_dsa_private_key.data.data());
                    }

                    hs = protocol::make_handshake(protocol::HandshakeRole::Responder, std::move(hcfg));
                    hs->set_send_fn([this, uav_id](Bytes wire) -> VoidResult {
                        return network_mgr_->send_message_to(uav_id, protocol::wrap_packet(protocol::ProtocolID::HANDSHAKE, wire));
                    });
                }
            }

            if (hs && hs->state() != protocol::HandshakeState::Complete && 
                hs->state() != protocol::HandshakeState::Failed) {
                
                auto res = hs->feed_message(payload);
                if (!res) {
                    std::cerr << "[GCS] Error: Handshake feed_message failed for UAV NodeId: "
                              << static_cast<int>(uav_id[0]) << ":" << static_cast<int>(uav_id[1])
                              << " - Error: " << res.error().message << std::endl;
                }
                if (res && hs->state() == protocol::HandshakeState::Complete) {
                    auto hres_r = hs->result();
                    if (hres_r) {
                        auto session = std::move(hres_r.value().session);
                        active_uav_sessions_[uav_id] = session.id();
                        session_mgr_->add_session(std::move(session), 0);
                        event_bus_->publish(std::string("Handshake Complete with UAV-00") + std::to_string(static_cast<int>(uav_id[1])));
                    }
                    handshakes_.erase(uav_id);
                }
            }
            break;
        }
        case protocol::ProtocolID::TELEMETRY: {
            if (uhdr.message_type == 1) {
                auto it = active_uav_sessions_.find(uav_id);
                if (it != active_uav_sessions_.end()) {
                    auto sess_r = session_mgr_->get_session(it->second, uav_id, 0);
                    if (sess_r) {
                        auto dec_r = sess_r.value()->decrypt(payload, ByteSpan{});
                        if (dec_r) {
                            std::cout << "[UI_EVENT] {\"event\": \"telemetry\", \"id\": \"UAV-00" << static_cast<int>(uav_id[1]) << "\"}" << std::endl;
                            event_bus_->publish(dec_r.value());
                            // Publish raw decrypted stream for loopback sniffing
                            event_bus_->publish(DecryptedMavlinkStream{dec_r.value()});

                            // Parse MAVLink stream
                            auto frames = mavlink_parser_.feed(reinterpret_cast<const uint8_t*>(dec_r.value().data()), dec_r.value().size());
                            for (const auto& frame : frames) {
                                event_bus_->publish(frame.payload);
                                
                                switch (frame.header.msgid) {
                                    case mavlink::Heartbeat::MSG_ID: {
                                        mavlink::Heartbeat hb;
                                        std::memcpy(&hb, frame.payload.data(), sizeof(hb));
                                        std::cout << "[MAVLINK GCS] Received HEARTBEAT: type=" << (int)hb.type 
                                                  << ", autopilot=" << (int)hb.autopilot 
                                                  << ", sys_status=" << (int)hb.system_status << std::endl;
                                        break;
                                    }
                                    case mavlink::SysStatus::MSG_ID: {
                                        mavlink::SysStatus status;
                                        std::memcpy(&status, frame.payload.data(), sizeof(status));
                                        std::cout << "[MAVLINK GCS] Received SYS_STATUS: load=" << status.load 
                                                  << ", voltage=" << status.voltage_battery 
                                                  << "mV, remaining=" << (int)status.battery_remaining << "%" << std::endl;
                                        break;
                                    }
                                    case mavlink::GpsRawInt::MSG_ID: {
                                        mavlink::GpsRawInt gps;
                                        std::memcpy(&gps, frame.payload.data(), sizeof(gps));
                                        std::cout << "[MAVLINK GCS] Received GPS_RAW_INT: lat=" << gps.lat / 1e7 
                                                  << ", lon=" << gps.lon / 1e7 
                                                  << ", sat_visible=" << (int)gps.satellites_visible << std::endl;
                                        break;
                                    }
                                    case mavlink::Attitude::MSG_ID: {
                                        mavlink::Attitude att;
                                        std::memcpy(&att, frame.payload.data(), sizeof(att));
                                        std::cout << "[MAVLINK GCS] Received ATTITUDE: roll=" << att.roll 
                                                  << ", pitch=" << att.pitch 
                                                  << ", yaw=" << att.yaw << std::endl;
                                        break;
                                    }
                                    case mavlink::LocalPositionNed::MSG_ID: {
                                        mavlink::LocalPositionNed pos;
                                        std::memcpy(&pos, frame.payload.data(), sizeof(pos));
                                        std::cout << "[MAVLINK GCS] Received LOCAL_POSITION_NED: x=" << pos.x 
                                                  << ", y=" << pos.y 
                                                  << ", z=" << pos.z << std::endl;
                                        break;
                                    }
                                    case mavlink::GlobalPositionInt::MSG_ID: {
                                        mavlink::GlobalPositionInt pos;
                                        std::memcpy(&pos, frame.payload.data(), sizeof(pos));
                                        std::cout << "[MAVLINK GCS] Received GLOBAL_POSITION_INT: lat=" << pos.lat / 1e7 
                                                  << ", lon=" << pos.lon / 1e7 
                                                  << ", alt=" << pos.alt / 1000.0 << "m, rel_alt=" << pos.relative_alt / 1000.0 << "m" << std::endl;
                                        break;
                                    }
                                    case mavlink::MissionCurrent::MSG_ID: {
                                        mavlink::MissionCurrent mis;
                                        std::memcpy(&mis, frame.payload.data(), sizeof(mis));
                                        std::cout << "[MAVLINK GCS] Received MISSION_CURRENT: seq=" << mis.seq << std::endl;
                                        break;
                                    }
                                    case mavlink::CommandLong::MSG_ID: {
                                        mavlink::CommandLong cmd;
                                        std::memcpy(&cmd, frame.payload.data(), sizeof(cmd));
                                        std::cout << "[MAVLINK GCS] Received COMMAND_LONG: command=" << cmd.command << std::endl;
                                        break;
                                    }
                                    case mavlink::BatteryStatus::MSG_ID: {
                                        mavlink::BatteryStatus batt;
                                        std::memcpy(&batt, frame.payload.data(), sizeof(batt));
                                        std::cout << "[MAVLINK GCS] Received BATTERY_STATUS: remaining=" << (int)batt.battery_remaining 
                                                  << "%, consumed=" << batt.current_consumed << "mAh" << std::endl;
                                        break;
                                    }
                                    default:
                                        std::cout << "[MAVLINK GCS] Received MAVLink frame with unknown MSG_ID: " << frame.header.msgid << std::endl;
                                        break;
                                }
                            }
                        } else {
                            std::cerr << "[GCS] Decryption error: " << dec_r.error().message << std::endl;
                            {
                                protocol::AlertMessage am{
                                    .level       = protocol::AlertLevel::Fatal,
                                    .code        = protocol::AlertCode::DecryptionFailed,
                                    .description = "Decryption Failed - Session Reset Required"
                                };
                                Bytes body = am.serialise();
                                protocol::MessageHeader hdr{
                                    .type            = protocol::MessageType::Alert,
                                    .length          = static_cast<std::uint16_t>(body.size()),
                                    .session_id      = {},
                                    .sequence_number = 0xFFFF
                                };
                                Bytes wire = hdr.serialise();
                                wire.insert(wire.end(), body.begin(), body.end());
                                
                                auto packet = protocol::wrap_packet(protocol::ProtocolID::HANDSHAKE, wire);
                                (void)network_mgr_->send_message_to(uav_id, packet);
                            }
                        }
                    } else {
                        std::cerr << "[GCS] Telemetry session not found" << std::endl;
                        {
                            protocol::AlertMessage am{
                                .level       = protocol::AlertLevel::Fatal,
                                .code        = protocol::AlertCode::DecryptionFailed,
                                .description = "Telemetry Session Not Found - Session Reset Required"
                            };
                            Bytes body = am.serialise();
                            protocol::MessageHeader hdr{
                                .type            = protocol::MessageType::Alert,
                                .length          = static_cast<std::uint16_t>(body.size()),
                                .session_id      = {},
                                .sequence_number = 0xFFFF
                            };
                            Bytes wire = hdr.serialise();
                            wire.insert(wire.end(), body.begin(), body.end());
                            
                            auto packet = protocol::wrap_packet(protocol::ProtocolID::HANDSHAKE, wire);
                            (void)network_mgr_->send_message_to(uav_id, packet);
                        }
                    }
                } else {
                    std::cerr << "[GCS] Active session not found for UAV" << std::endl;
                    {
                        protocol::AlertMessage am{
                            .level       = protocol::AlertLevel::Fatal,
                            .code        = protocol::AlertCode::DecryptionFailed,
                            .description = "Active Session Not Found - Session Reset Required"
                        };
                        Bytes body = am.serialise();
                        protocol::MessageHeader hdr{
                            .type            = protocol::MessageType::Alert,
                            .length          = static_cast<std::uint16_t>(body.size()),
                            .session_id      = {},
                            .sequence_number = 0xFFFF
                        };
                        Bytes wire = hdr.serialise();
                        wire.insert(wire.end(), body.begin(), body.end());
                        
                        auto packet = protocol::wrap_packet(protocol::ProtocolID::HANDSHAKE, wire);
                        (void)network_mgr_->send_message_to(uav_id, packet);
                    }
                }
            } else {
                event_bus_->publish(payload);
            }
            break;
        }
        case protocol::ProtocolID::VIDEO: {
            if (uhdr.message_type == 1) {
                auto it = active_uav_sessions_.find(uav_id);
                if (it != active_uav_sessions_.end()) {
                    auto sess_r = session_mgr_->get_session(it->second, uav_id, 0);
                    if (sess_r) {
                        auto dec_r = sess_r.value()->decrypt(payload, ByteSpan{});
                        if (dec_r) {
                            event_bus_->publish(DecryptedVideoFrame{uav_id, dec_r.value()});
                        } else {
                            std::cerr << "[GCS] Video frame decryption failed" << std::endl;
                        }
                    }
                }
            }
            break;
        }
        case protocol::ProtocolID::COMMAND:
        case protocol::ProtocolID::TREEKEM:
        case protocol::ProtocolID::HEARTBEAT: {
            event_bus_->publish(payload);
            break;
        }
        case protocol::ProtocolID::D2D: {
            // D2D Session Coordination Message
            if (uhdr.message_type == static_cast<std::uint8_t>(protocol::MessageType::D2DSessionReq)) {
                // Decrypt request payload if encrypted using UAV's GCS session
                Bytes req_bytes = payload;
                auto sess_it = active_uav_sessions_.find(uav_id);
                if (sess_it != active_uav_sessions_.end()) {
                    auto sess_r = session_mgr_->get_session(sess_it->second, uav_id, 0);
                    if (sess_r) {
                        auto dec_r = sess_r.value()->decrypt(payload, ByteSpan{});
                        if (dec_r) {
                            req_bytes = dec_r.value();
                        }
                    }
                }

                auto req_r = protocol::D2DSessionReqPayload::deserialize(req_bytes);
                if (req_r) {
                    const auto& req = req_r.value();
                    NodeId target_id = req.target_node_id;

                    bool init_active = (active_uav_sessions_.find(uav_id) != active_uav_sessions_.end());
                    bool target_active = (active_uav_sessions_.find(target_id) != active_uav_sessions_.end());

                    std::string target_ip = "127.0.0.1";
                    std::uint16_t target_port = 9000 + static_cast<std::uint16_t>(target_id[1]);
                    std::string init_ip = "127.0.0.1";
                    std::uint16_t init_port = 9000 + static_cast<std::uint16_t>(uav_id[1]);

                    policy::PolicyContext ctx;
                    Timestamp now_ms = static_cast<Timestamp>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

                    auto coord_res = d2d_coordinator_.coordinate_session_request(
                        req, init_active, target_active,
                        target_ip, target_port, init_ip, init_port,
                        ctx, now_ms);

                    if (coord_res) {
                        auto [resp_init, resp_target] = std::move(coord_res.value());
                        Bytes init_body = resp_init.serialize();
                        Bytes target_body = resp_target.serialize();

                        // Encrypt and send response to Initiator (UAV-A)
                        auto init_sess = session_mgr_->get_session(active_uav_sessions_[uav_id], uav_id, 0);
                        if (init_sess) {
                            auto enc_init = init_sess.value()->encrypt(init_body, ByteSpan{});
                            if (enc_init) {
                                Bytes wire = protocol::wrap_packet(protocol::ProtocolID::D2D, enc_init.value(), static_cast<std::uint8_t>(protocol::MessageType::D2DSessionResp));
                                network_mgr_->send_message_to(uav_id, wire);
                            }
                        }

                        // Encrypt and send response to Target (UAV-B)
                        auto target_sess = session_mgr_->get_session(active_uav_sessions_[target_id], target_id, 0);
                        if (target_sess) {
                            auto enc_target = target_sess.value()->encrypt(target_body, ByteSpan{});
                            if (enc_target) {
                                Bytes wire = protocol::wrap_packet(protocol::ProtocolID::D2D, enc_target.value(), static_cast<std::uint8_t>(protocol::MessageType::D2DSessionResp));
                                network_mgr_->send_message_to(target_id, wire);
                            }
                        }
                    } else {
                        // Send rejection back to Initiator
                        protocol::D2DSessionRejectPayload rej;
                        rej.initiator_node_id = uav_id;
                        rej.target_node_id = target_id;
                        rej.reason_code = protocol::D2DRejectReason::PolicyDenied;
                        rej.reason_msg = "D2D session request unauthorized";

                        Bytes rej_body = rej.serialize();
                        auto init_sess = session_mgr_->get_session(active_uav_sessions_[uav_id], uav_id, 0);
                        if (init_sess) {
                            auto enc_rej = init_sess.value()->encrypt(rej_body, ByteSpan{});
                            if (enc_rej) {
                                Bytes wire = protocol::wrap_packet(protocol::ProtocolID::D2D, enc_rej.value(), static_cast<std::uint8_t>(protocol::MessageType::D2DSessionReject));
                                network_mgr_->send_message_to(uav_id, wire);
                            }
                        }
                    }
                }
            }
            break;
        }
    }
}

std::vector<NodeId> GroundControlStation::get_active_uavs() const {
    std::vector<NodeId> list;
    for (const auto& pair : active_uav_sessions_) {
        list.push_back(pair.first);
    }
    return list;
}

} // namespace uav_pqc::app
