// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/uav.hpp"

#include "uav_pqc/crypto/default_provider.hpp"
#include "uav_pqc/group/tree_kem.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

#include <dirent.h>
#include <sys/stat.h>

namespace uav_pqc::app {

Uav::Uav(std::shared_ptr<IEventBus> event_bus,
         std::shared_ptr<IConfigurationManager> config_mgr,
         std::shared_ptr<ICryptoManager> crypto_mgr,
         std::shared_ptr<INetworkManager> network_mgr,
         std::shared_ptr<ISessionManager> session_mgr,
         std::shared_ptr<IAcpeEngine> acpe_engine)
    : event_bus_(std::move(event_bus)), config_mgr_(std::move(config_mgr)),
      crypto_mgr_(std::move(crypto_mgr)), network_mgr_(std::move(network_mgr)),
      session_mgr_(std::move(session_mgr)), acpe_engine_(std::move(acpe_engine)) {
    treekem_ctrl_ = std::make_shared<TreeKemController>(
        protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256));

    network_mgr_->set_message_handler([this](const NodeId& src_id, const Bytes& msg) {
        this->handle_reassembled_message(src_id, msg);
    });
}

VoidResult Uav::initialize(const std::string& config_str) {
    auto cfg_r = config_mgr_->load_from_string(config_str);
    if (!cfg_r)
        return err(cfg_r.error());

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

    // Parse JSON config for mission profile and battery capacity
    try {
        nlohmann::json j = nlohmann::json::parse(config_str);
        if (j.contains("mission")) {
            std::string m_name = j["mission"].get<std::string>();
            if (m_name == "Surveillance") {
                mission_.type                           = UavMissionType::Surveillance;
                mission_.criticality                    = 6.0;
                mission_.speed_m_s                      = 10.0;
                mission_.target_altitude                = 50.0;
                mission_.default_operating_mode         = protocol::OperatingMode::Hybrid;
                mission_.default_crypto_profile         = policy::CryptographicProfile::Standard;
                mission_.telemetry_interval_sec         = 1.0;
                mission_.payload_size                   = 800;
                mission_.preferred_cipher_suite         = "MLKEM768-MLDSA65-AES256GCM";
                mission_.treekem_rekey_interval_sec     = 30.0;
                mission_.session_lifetime_sec           = 1200;
                mission_.battery_consumption_multiplier = 1.0;
                mission_.communication_priority         = 5.0;
                mission_.neighbor_sync_rate             = 1.0;
                mission_.video_streaming_enabled        = true;

                telemetry_interval_ms_      = 1000.0;
                payload_size_               = 800;
                battery_.p_hover            = 150.0;
                battery_.c_drag             = 0.08;
                treekem_rekey_interval_sec_ = 30.0;
                threat_level_               = policy::ThreatLevel::Medium;
            } else if (m_name == "Patrol") {
                mission_.type                           = UavMissionType::Patrol;
                mission_.criticality                    = 5.0;
                mission_.speed_m_s                      = 20.0;
                mission_.target_altitude                = 80.0;
                mission_.default_operating_mode         = protocol::OperatingMode::Hybrid;
                mission_.default_crypto_profile         = policy::CryptographicProfile::Lightweight;
                mission_.telemetry_interval_sec         = 2.0;
                mission_.payload_size                   = 400;
                mission_.preferred_cipher_suite         = "MLKEM512-MLDSA44-AES128GCM";
                mission_.treekem_rekey_interval_sec     = 30.0;
                mission_.session_lifetime_sec           = 600;
                mission_.battery_consumption_multiplier = 1.2;
                mission_.communication_priority         = 4.0;
                mission_.neighbor_sync_rate             = 0.5;
                mission_.video_streaming_enabled        = false;

                telemetry_interval_ms_      = 2000.0;
                payload_size_               = 400;
                battery_.p_hover            = 200.0;
                battery_.c_drag             = 0.1;
                treekem_rekey_interval_sec_ = 30.0;
                threat_level_               = policy::ThreatLevel::Medium;
            } else if (m_name == "Delivery") {
                mission_.type                           = UavMissionType::Delivery;
                mission_.criticality                    = 3.0;
                mission_.speed_m_s                      = 25.0;
                mission_.target_altitude                = 100.0;
                mission_.default_operating_mode         = protocol::OperatingMode::Transition;
                mission_.default_crypto_profile         = policy::CryptographicProfile::Lightweight;
                mission_.telemetry_interval_sec         = 5.0;
                mission_.payload_size                   = 0;
                mission_.preferred_cipher_suite         = "MLKEM512-MLDSA44-AES128GCM";
                mission_.treekem_rekey_interval_sec     = 45.0;
                mission_.session_lifetime_sec           = 300;
                mission_.battery_consumption_multiplier = 1.5;
                mission_.communication_priority         = 3.0;
                mission_.neighbor_sync_rate             = 0.2;
                mission_.video_streaming_enabled        = false;

                telemetry_interval_ms_      = 5000.0;
                payload_size_               = 0;
                battery_.p_hover            = 350.0;
                battery_.c_drag             = 0.15;
                treekem_rekey_interval_sec_ = 30.0;
                threat_level_               = policy::ThreatLevel::Medium;
            } else if (m_name == "SearchRescue" || m_name == "Search & Rescue") {
                mission_.type                           = UavMissionType::SearchRescue;
                mission_.criticality                    = 9.0;
                mission_.speed_m_s                      = 5.0;
                mission_.target_altitude                = 30.0;
                mission_.default_operating_mode         = protocol::OperatingMode::PqcOnly;
                mission_.default_crypto_profile         = policy::CryptographicProfile::Hardened;
                mission_.telemetry_interval_sec         = 0.5;
                mission_.payload_size                   = 400;
                mission_.preferred_cipher_suite         = "MLKEM1024-MLDSA87-AES256GCM";
                mission_.treekem_rekey_interval_sec     = 15.0;
                mission_.session_lifetime_sec           = 240;
                mission_.battery_consumption_multiplier = 1.3;
                mission_.communication_priority         = 9.0;
                mission_.neighbor_sync_rate             = 2.0;
                mission_.video_streaming_enabled        = true;

                telemetry_interval_ms_      = 500.0;
                payload_size_               = 400;
                battery_.p_hover            = 250.0;
                battery_.c_drag             = 0.12;
                treekem_rekey_interval_sec_ = 15.0;
                threat_level_               = policy::ThreatLevel::High;
            } else if (m_name == "Formation" || m_name == "Formation Flight") {
                mission_.type                           = UavMissionType::Formation;
                mission_.criticality                    = 8.0;
                mission_.speed_m_s                      = 12.0;
                mission_.target_altitude                = 40.0;
                mission_.default_operating_mode         = protocol::OperatingMode::Hybrid;
                mission_.default_crypto_profile         = policy::CryptographicProfile::Standard;
                mission_.telemetry_interval_sec         = 0.5;
                mission_.payload_size                   = 100;
                mission_.preferred_cipher_suite         = "MLKEM768-MLDSA65-AES256GCM";
                mission_.treekem_rekey_interval_sec     = 5.0;
                mission_.session_lifetime_sec           = 600;
                mission_.battery_consumption_multiplier = 1.1;
                mission_.communication_priority         = 7.0;
                mission_.neighbor_sync_rate             = 5.0;
                mission_.video_streaming_enabled        = false;

                telemetry_interval_ms_      = 500.0;
                payload_size_               = 100;
                battery_.p_hover            = 220.0;
                battery_.c_drag             = 0.1;
                treekem_rekey_interval_sec_ = 5.0;
                threat_level_               = policy::ThreatLevel::High;
            }
        }

        // Parse dynamic configuration override inputs if they exist
        if (j.contains("telemetry_interval_sec"))
            mission_.telemetry_interval_sec = j["telemetry_interval_sec"].get<double>();
        if (j.contains("payload_size"))
            mission_.payload_size = j["payload_size"].get<std::uint32_t>();
        if (j.contains("battery_consumption_multiplier"))
            mission_.battery_consumption_multiplier =
                j["battery_consumption_multiplier"].get<double>();
        if (j.contains("communication_priority"))
            mission_.communication_priority = j["communication_priority"].get<double>();
        if (j.contains("neighbor_sync_rate"))
            mission_.neighbor_sync_rate = j["neighbor_sync_rate"].get<double>();
        if (j.contains("video_streaming_enabled"))
            mission_.video_streaming_enabled = j["video_streaming_enabled"].get<bool>();
        if (j.contains("preferred_cipher_suite"))
            mission_.preferred_cipher_suite = j["preferred_cipher_suite"].get<std::string>();
        if (j.contains("p_cpu_idle"))
            battery_.p_cpu_idle = j["p_cpu_idle"].get<double>();
        if (j.contains("battery_capacity")) {
            double cap                       = j["battery_capacity"].get<double>();
            battery_.total_capacity_joules   = cap;
            battery_.remaining_energy_joules = cap;
        }

        // ── Custom JSON Overrides ────────────────────────────────────────────
        if (j.contains("speed"))
            mission_.speed_m_s = j["speed"].get<double>();
        if (j.contains("criticality"))
            mission_.criticality = j["criticality"].get<double>();
        if (j.contains("target_altitude"))
            mission_.target_altitude = j["target_altitude"].get<double>();
        if (j.contains("telemetry_interval_ms"))
            telemetry_interval_ms_ = j["telemetry_interval_ms"].get<double>();
        if (j.contains("payload_size"))
            payload_size_ = j["payload_size"].get<std::uint32_t>();
        if (j.contains("treekem_rekey_interval_sec"))
            treekem_rekey_interval_sec_ = j["treekem_rekey_interval_sec"].get<double>();

        if (j.contains("threat_level")) {
            std::string t_name = j["threat_level"].get<std::string>();
            if (t_name == "Low")
                threat_level_ = policy::ThreatLevel::Low;
            else if (t_name == "Medium")
                threat_level_ = policy::ThreatLevel::Medium;
            else if (t_name == "High")
                threat_level_ = policy::ThreatLevel::High;
        }

        // Battery Model coefficients overrides
        if (j.contains("p_hover"))
            battery_.p_hover = j["p_hover"].get<double>();
        if (j.contains("c_drag"))
            battery_.c_drag = j["c_drag"].get<double>();
        if (j.contains("p_climb"))
            battery_.p_climb = j["p_climb"].get<double>();
        if (j.contains("p_descend"))
            battery_.p_descend = j["p_descend"].get<double>();
        if (j.contains("e_tx_per_byte"))
            battery_.e_tx_per_byte = j["e_tx_per_byte"].get<double>();
        if (j.contains("e_rx_per_byte"))
            battery_.e_rx_per_byte = j["e_rx_per_byte"].get<double>();
        if (j.contains("e_ml_kem_encaps"))
            battery_.e_ml_kem_encaps = j["e_ml_kem_encaps"].get<double>();
        if (j.contains("e_ml_kem_decaps"))
            battery_.e_ml_kem_decaps = j["e_ml_kem_decaps"].get<double>();
        if (j.contains("e_ml_dsa_sign"))
            battery_.e_ml_dsa_sign = j["e_ml_dsa_sign"].get<double>();
        if (j.contains("e_ml_dsa_verify"))
            battery_.e_ml_dsa_verify = j["e_ml_dsa_verify"].get<double>();
        if (j.contains("e_symmetric_per_byte"))
            battery_.e_symmetric_per_byte = j["e_symmetric_per_byte"].get<double>();
        if (j.contains("e_treekem_operation"))
            battery_.e_treekem_operation = j["e_treekem_operation"].get<double>();
        if (j.contains("e_x25519_keygen"))
            battery_.e_x25519_keygen = j["e_x25519_keygen"].get<double>();
        if (j.contains("e_x25519_encaps"))
            battery_.e_x25519_encaps = j["e_x25519_encaps"].get<double>();
        if (j.contains("e_x25519_decaps"))
            battery_.e_x25519_decaps = j["e_x25519_decaps"].get<double>();
        if (j.contains("e_ecdsa_sign"))
            battery_.e_ecdsa_sign = j["e_ecdsa_sign"].get<double>();
        if (j.contains("e_ecdsa_verify"))
            battery_.e_ecdsa_verify = j["e_ecdsa_verify"].get<double>();
        if (j.contains("e_ml_kem_keygen"))
            battery_.e_ml_kem_keygen = j["e_ml_kem_keygen"].get<double>();
        if (j.contains("e_ml_dsa_keygen"))
            battery_.e_ml_dsa_keygen = j["e_ml_dsa_keygen"].get<double>();
    } catch (...) {
        return err(ErrorCode::InvalidArgument, "Failed to parse JSON config in UAV initialize");
    }

    return ok();
}

VoidResult Uav::start_handshake(Timestamp now_ms) {
    if (shutdown_initiated_ || battery_level_ <= 0.0) {
        return err(ErrorCode::UnsupportedOperation, "UAV is shutdown");
    }

    protocol::HandshakeConfig hcfg;
    const auto& app_cfg = config_mgr_->get_config();

    hcfg.our_node_id   = node_id_;
    hcfg.offered_modes = app_cfg.offered_modes;
    hcfg.timeout_ms    = 10000;

    // Setup certificates and keys for testing/emulation
    if (!cert_.empty()) {
        hcfg.our_certificate = cert_;
    } else {
        hcfg.our_certificate = {std::byte{0x01}, std::byte{0x02}};
    }
    const auto& static_kp = crypto_mgr_->get_static_dsa_keypair();
    if (static_kp) {
        hcfg.our_dsa_private_key.data.resize(static_kp->private_key.size());
        std::copy(static_kp->private_key.span().begin(),
                  static_kp->private_key.span().end(),
                  hcfg.our_dsa_private_key.data.data());

        hcfg.our_ml_dsa_private_key.data.resize(static_kp->private_key.size());
        std::copy(static_kp->private_key.span().begin(),
                  static_kp->private_key.span().end(),
                  hcfg.our_ml_dsa_private_key.data.data());
    }

    auto primary_mode =
        hcfg.offered_modes.empty() ? protocol::OperatingMode::Hybrid : hcfg.offered_modes.front();

    handshake_ = protocol::make_handshake(protocol::HandshakeRole::Initiator, std::move(hcfg));

    handshake_->set_send_fn([this](Bytes wire) -> VoidResult {
        if (shutdown_initiated_)
            return err(ErrorCode::UnsupportedOperation, "UAV is shutdown");
        packets_sent_++;
        // Consume energy for sending a handshake message
        battery_.consume_tx(wire.size() + protocol::UniversalHeader::kWireSize);
        return network_mgr_->send_message_to(
            NodeId{},
            protocol::wrap_packet(protocol::ProtocolID::HANDSHAKE, wire));
    });

    // Deduct initiating KEM keypair generation costs
    if (primary_mode == protocol::OperatingMode::Classical) {
        battery_.consume_crypto_x25519_keygen();
    } else if (primary_mode == protocol::OperatingMode::Transition ||
               primary_mode == protocol::OperatingMode::PqcOnly) {
        battery_.consume_crypto_ml_kem_keygen();
    } else if (primary_mode == protocol::OperatingMode::Hybrid) {
        battery_.consume_crypto_x25519_keygen();
        battery_.consume_crypto_ml_kem_keygen();
    }

    return handshake_->start();
}

VoidResult Uav::receive_packet(ByteSpan packet, Timestamp now_ms) {
    if (shutdown_initiated_ || battery_level_ <= 0.0) {
        return err(ErrorCode::UnsupportedOperation, "UAV is shutdown");
    }
    packets_received_++;
    return network_mgr_->handle_incoming_packet(packet, now_ms);
}

VoidResult Uav::send_telemetry(ByteSpan payload, Timestamp now_ms) {
    if (shutdown_initiated_ || battery_level_ <= 0.0) {
        return err(ErrorCode::UnsupportedOperation, "UAV is shutdown");
    }

    // Publish raw telemetry stream for loopback sniffing
    event_bus_->publish(DecryptedMavlinkStream{Bytes(payload.begin(), payload.end())});

    // ── Emergency and Low Battery Communication Restrictions ──────────────────
    if (battery_level_ < 10.0) {
        // Transmit only Heartbeat, Battery, Position, Emergency status (essential/small payloads)
        if (payload.size() > 100) {
            std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                      << static_cast<int>(node_id_[1])
                      << "] Emergency Mode (<10%): Rejecting non-essential payload of size "
                      << payload.size() << " bytes." << std::endl;
            return err(ErrorCode::UnsupportedOperation,
                       "Emergency Mode: non-essential telemetry suspended");
        }
    } else if (battery_level_ < 20.0) {
        // Suspend non-essential payload traffic
        if (payload.size() > 250) {
            std::cout
                << "[UAV-" << static_cast<int>(node_id_[0]) << ":" << static_cast<int>(node_id_[1])
                << "] Emergency profile (<20%): Suspending non-essential payload traffic of size "
                << payload.size() << " bytes." << std::endl;
            return err(ErrorCode::UnsupportedOperation,
                       "Low Battery: non-essential telemetry suspended");
        }
    } else if (battery_level_ < 40.0) {
        // Aggressively reduce communication (limit payload sizes to 500 bytes)
        if (payload.size() > 500) {
            std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                      << static_cast<int>(node_id_[1])
                      << "] Battery 20%-40%: Throttling large telemetry of size " << payload.size()
                      << " bytes." << std::endl;
            return err(ErrorCode::UnsupportedOperation,
                       "Battery 20%-40%: large telemetry throttled");
        }
    }

    packets_sent_++;
    // Consume energy for symmetric encryption and packet transmission
    battery_.consume_crypto_symmetric(payload.size());
    battery_.consume_tx(payload.size() + protocol::UniversalHeader::kWireSize);

    auto sess_r = session_mgr_->get_session(active_session_id_, active_peer_id_, now_ms);
    if (!sess_r) {
        return err(ErrorCode::UnsupportedOperation, "No active secure session");
    }

    auto enc_r = sess_r.value()->encrypt(payload, ByteSpan{});
    if (!enc_r)
        return err(enc_r.error());

    return network_mgr_->send_message_to(NodeId{}, protocol::wrap_packet(
        protocol::ProtocolID::TELEMETRY, enc_r.value(), 1, active_session_id_));
}

VoidResult Uav::send_video_frame(
    ByteSpan jpeg_bytes, uint16_t width, uint16_t height, uint32_t frame_seq, Timestamp now_ms) {
    if (shutdown_initiated_ || battery_level_ <= 0.0) {
        return err(ErrorCode::UnsupportedOperation, "UAV is shutdown");
    }

    // Prepare packet payload
    Bytes payload;
    payload.reserve(12 + jpeg_bytes.size());

    // Write timestamp
    uint32_t ts = static_cast<uint32_t>(now_ms & 0xFFFFFFFF);
    uint8_t ts_buf[4];
    std::memcpy(ts_buf, &ts, 4);
    payload.insert(payload.end(),
                   reinterpret_cast<const std::byte*>(ts_buf),
                   reinterpret_cast<const std::byte*>(ts_buf) + 4);

    // Write sequence
    uint8_t seq_buf[4];
    std::memcpy(seq_buf, &frame_seq, 4);
    payload.insert(payload.end(),
                   reinterpret_cast<const std::byte*>(seq_buf),
                   reinterpret_cast<const std::byte*>(seq_buf) + 4);

    // Write width and height
    uint8_t w_buf[2], h_buf[2];
    std::memcpy(w_buf, &width, 2);
    std::memcpy(h_buf, &height, 2);
    payload.insert(payload.end(),
                   reinterpret_cast<const std::byte*>(w_buf),
                   reinterpret_cast<const std::byte*>(w_buf) + 2);
    payload.insert(payload.end(),
                   reinterpret_cast<const std::byte*>(h_buf),
                   reinterpret_cast<const std::byte*>(h_buf) + 2);

    // Append JPEG data
    payload.insert(payload.end(), jpeg_bytes.begin(), jpeg_bytes.end());

    packets_sent_++;
    // Consume energy for symmetric encryption and packet transmission
    battery_.consume_crypto_symmetric(payload.size());
    battery_.consume_tx(payload.size() + protocol::UniversalHeader::kWireSize);

    auto sess_r = session_mgr_->get_session(active_session_id_, active_peer_id_, 0);
    if (!sess_r) {
        return err(ErrorCode::SessionNotFound, "No active session with GCS for video");
    }

    auto enc_r = sess_r.value()->encrypt(payload, ByteSpan{});
    if (!enc_r)
        return err(enc_r.error());

    // Wrap packet as ProtocolID::VIDEO and transmit unreliably
    return network_mgr_->send_message_to(NodeId{},
        protocol::wrap_packet(protocol::ProtocolID::VIDEO, enc_r.value(), 1, active_session_id_));
}

void Uav::set_battery_level(double percent, Timestamp now_ms) {
    battery_level_ = percent;

    policy::PolicyContext ctx;
    ctx.battery_percent = static_cast<std::uint8_t>(percent);
    ctx.hardware_class  = policy::HardwareClass::EmbeddedLinux;

    // Dynamic context updates based on the current mission and speed
    ctx.speed_m_s           = static_cast<float>(mission_.speed_m_s);
    ctx.mission_criticality = mission_.criticality;
    ctx.threat_level        = threat_level_;

    // Mission-aware policy properties
    ctx.default_operating_mode         = mission_.default_operating_mode;
    ctx.default_crypto_profile         = mission_.default_crypto_profile;
    ctx.telemetry_interval_sec         = mission_.telemetry_interval_sec;
    ctx.payload_size                   = mission_.payload_size;
    ctx.preferred_cipher_suite         = mission_.preferred_cipher_suite;
    ctx.treekem_rekey_interval_sec     = mission_.treekem_rekey_interval_sec;
    ctx.session_lifetime_sec_limit     = mission_.session_lifetime_sec;
    ctx.battery_consumption_multiplier = mission_.battery_consumption_multiplier;
    ctx.communication_priority         = mission_.communication_priority;
    ctx.neighbor_sync_rate             = mission_.neighbor_sync_rate;
    ctx.video_streaming_enabled        = mission_.video_streaming_enabled;

    // Realistic multi-dimensional inputs
    double mapped_rssi   = link_rssi_;
    std::uint32_t ip_val = 0;
    std::memcpy(&ip_val, node_id_.data(), 4);
    bool is_lte = (((ip_val >> 24) & 0xFF) == 7);
    if (is_lte) {
        if (link_rssi_ > -80.0) {
            mapped_rssi = -50.0;
        } else if (link_rssi_ < -115.0) {
            mapped_rssi = -90.0;
        } else {
            mapped_rssi = (link_rssi_ + 115.0) * (40.0 / 35.0) - 90.0;
        }
    }
    ctx.rssi                 = mapped_rssi;
    ctx.sinr                 = link_sinr_;
    ctx.packet_loss          = link_packet_loss_;
    ctx.latency_ms           = link_latency_ms_;
    ctx.session_lifetime_sec = get_session_lifetime_sec(now_ms);
    ctx.treekem_update_freq =
        (treekem_rekeys_ > 0 && ctx.session_lifetime_sec > 0.0)
            ? (static_cast<double>(treekem_rekeys_) / (ctx.session_lifetime_sec / 60.0))
            : 0.0;
    ctx.security_downgrade_threshold = config_mgr_->get_config().security_downgrade_threshold;

    // Map D2D syncing CPU utilization
    ctx.cpu_utilization = 15.0;  // Baseline CPU
    if (mission_.type == UavMissionType::Formation) {
        ctx.cpu_utilization += 20.0;
    }

    auto dec_r = acpe_engine_->evaluate_context(ctx);
    if (dec_r) {
        last_decision_ = dec_r.value();
        event_bus_->publish(dec_r.value());

        // Update telemetry and payload policies dynamically
        telemetry_interval_ms_      = dec_r.value().telemetry_interval_ms;
        payload_size_               = dec_r.value().payload_size;
        treekem_rekey_interval_sec_ = dec_r.value().treekem_rekey_interval_sec;

        if (dec_r.value().classical_recommended && !shutdown_initiated_) {
            if (!classical_approved_) {
                if (!waiting_for_classical_approval_) {
                    waiting_for_classical_approval_ = true;
                    std::cout << "[ACPE RECOMMENDATION] Generate Secure Policy Recommendation: "
                                 "ACPE suggests Classical Mode due to "
                              << dec_r.value().rationale << std::endl;
                    std::cout << "[ACPE RECOMMENDATION DETAIL] RecommendedMode=Classical"
                              << " Reason=\"" << dec_r.value().recommendation_reason << "\""
                              << " Timestamp=" << dec_r.value().recommendation_timestamp
                              << " ID=" << dec_r.value().recommendation_id << std::endl;

                    mavlink::CommandLong cmd_rec{};
                    cmd_rec.command = 50002;
                    cmd_rec.param1  = 1.0f;  // Classical Mode recommendation
                    cmd_rec.param2  = static_cast<float>(ctx.battery_percent);
                    cmd_rec.param3 =
                        ctx.rssi < -80.0 ? 1.0f : (ctx.packet_loss > 30.0 ? 2.0f : 3.0f);

                    std::vector<uint8_t> rec_stream(sizeof(cmd_rec));
                    std::memcpy(rec_stream.data(), &cmd_rec, sizeof(cmd_rec));
                    Bytes payload_bytes(
                        reinterpret_cast<const std::byte*>(rec_stream.data()),
                        reinterpret_cast<const std::byte*>(rec_stream.data()) + rec_stream.size());
                    send_telemetry(payload_bytes, now_ms);
                }
                std::cout << "[ACPE BLOCKED] Automatic Classical mode downgrade blocked. Waiting "
                             "for GCS approval..."
                          << std::endl;
                return;
            }
        }

        // Dynamically enforce renegotiation when the policy shifts
        if (dec_r.value().rekey_now && !shutdown_initiated_) {
            std::cout << "[ACPE UAV-" << static_cast<int>(node_id_[0]) << ":"
                      << static_cast<int>(node_id_[1])
                      << "] Policy changed due to battery=" << static_cast<int>(percent)
                      << "%, initiating renegotiation to mode="
                      << static_cast<int>(dec_r.value().mode) << std::endl;
            std::cout << "[ACPE UAV-" << static_cast<int>(node_id_[0]) << ":"
                      << static_cast<int>(node_id_[1]) << "] Rationale: " << dec_r.value().rationale
                      << std::endl;

            auto& config         = const_cast<AppConfig&>(config_mgr_->get_config());
            config.offered_modes = {dec_r.value().mode};

            start_handshake(now_ms);
        }
    }
}

void Uav::update_battery(Timestamp now_ms, double speed_m_s, double climb_rate) {
    if (shutdown_initiated_)
        return;

    if (last_battery_update_ms_ == 0) {
        last_battery_update_ms_ = now_ms;
        return;
    }
    double dt               = static_cast<double>(now_ms - last_battery_update_ms_) / 1000.0;
    last_battery_update_ms_ = now_ms;

    if (dt > 0.0) {
        mission_.speed_m_s = speed_m_s;

        double power_hover    = battery_.p_hover * mission_.battery_consumption_multiplier;
        double power_movement = (battery_.c_drag * (speed_m_s * speed_m_s * speed_m_s));
        if (climb_rate > 0.0) {
            power_movement += battery_.p_climb * climb_rate;
        } else if (climb_rate < 0.0) {
            power_movement += battery_.p_descend * climb_rate;
        }
        power_movement *= mission_.battery_consumption_multiplier;

        double power_cpu_idle = battery_.p_cpu_idle * mission_.battery_consumption_multiplier;

        double e_hover = power_hover * dt;
        double e_move  = power_movement * dt;
        double e_cpu   = power_cpu_idle * dt;

        battery_.remaining_energy_joules -= (e_hover + e_move + e_cpu);
        battery_.energy_flight += (e_hover + e_move);
        battery_.energy_cpu_idle += e_cpu;

        if (battery_.remaining_energy_joules < 0.0) {
            battery_.remaining_energy_joules = 0.0;
        }

        double new_pct = battery_.get_percent();
        set_battery_level(new_pct, now_ms);

        // ── Orderly Shutdown Sequence ─────────────────────────────────────────
        if (new_pct <= 0.0 && !shutdown_initiated_) {
            shutdown_initiated_ = true;
            std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                      << static_cast<int>(node_id_[1])
                      << "] 0% battery reached! Initiating orderly shutdown sequence." << std::endl;

            // 1. Stop mission
            mission_.speed_m_s = 0.0;

            // 2. Notify GCS & transmit final status
            Bytes final_status =
                protocol::wrap_packet(protocol::ProtocolID::HEARTBEAT, Bytes{std::byte{0x00}}, 0);
            network_mgr_->send_message(final_status);

            // 3. Terminate active sessions & Invalidate session keys
            session_mgr_->clear_sessions();
            active_session_id_ = SessionId{};

            // 4. Disconnect & leave TreeKEM (handled via session deletion)
            std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                      << static_cast<int>(node_id_[1])
                      << "] TreeKEM group left. Sessions terminated. Disconnected." << std::endl;
        }
    }
}

std::string Uav::get_mission_name() const noexcept {
    switch (mission_.type) {
        case UavMissionType::Surveillance:
            return "Surveillance";
        case UavMissionType::Patrol:
            return "Patrol";
        case UavMissionType::Delivery:
            return "Delivery";
        case UavMissionType::SearchRescue:
            return "Search & Rescue";
        case UavMissionType::Formation:
            return "Formation Flight";
    }
    return "Surveillance";
}

static std::string get_query_root() {
    if (const char* env = std::getenv("AETHER_UAV_QUERY_ROOT")) {
        return env;
    }
    return "./uav_media";
}

static bool is_path_safe(const std::string& requested, const std::string& allowed_root) {
    try {
        std::filesystem::path req_path(requested);
        std::filesystem::path root_path(allowed_root);

        // Resolve absolute paths
        std::filesystem::path req_canon =
            std::filesystem::weakly_canonical(std::filesystem::absolute(req_path));
        std::filesystem::path root_canon =
            std::filesystem::weakly_canonical(std::filesystem::absolute(root_path));

        // Block traversal outside of the allowed directory
        auto req_str  = req_canon.string();
        auto root_str = root_canon.string();

        if (!root_str.empty() && root_str.back() != std::filesystem::path::preferred_separator) {
            root_str += std::filesystem::path::preferred_separator;
        }

        if (req_str.rfind(root_str, 0) != 0) {
            return false;
        }

        // Block access to critical credentials, users db, and key folders
        std::string lower_req = req_str;
        std::transform(lower_req.begin(), lower_req.end(), lower_req.begin(), ::tolower);
        if (lower_req.find("users.json") != std::string::npos ||
            lower_req.find(".key") != std::string::npos ||
            lower_req.find(".pem") != std::string::npos ||
            lower_req.find("private") != std::string::npos ||
            lower_req.find("etc/") != std::string::npos ||
            lower_req.find("proc/") != std::string::npos ||
            lower_req.find("dev/") != std::string::npos) {
            return false;
        }

        return true;
    } catch (...) {
        return false;
    }
}

void Uav::handle_reassembled_message(const NodeId& src_id, const Bytes& msg) {
    if (shutdown_initiated_)
        return;

    auto uhdr_r = protocol::UniversalHeader::deserialise(msg);
    if (!uhdr_r) {
        std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                  << static_cast<int>(node_id_[1])
                  << "] Error deserialising universal header: " << uhdr_r.error().message
                  << std::endl;
        return;
    }

    const auto& uhdr = uhdr_r.value();

    if (msg.size() < protocol::UniversalHeader::kWireSize + uhdr.payload_length) {
        std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                  << static_cast<int>(node_id_[1]) << "] Error: Truncated universal packet body"
                  << std::endl;
        return;
    }

    Bytes payload(msg.begin() + protocol::UniversalHeader::kWireSize,
                  msg.begin() + protocol::UniversalHeader::kWireSize + uhdr.payload_length);

    std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":" << static_cast<int>(node_id_[1])
              << "] handle_reassembled_message: protocol_id=" << static_cast<int>(uhdr.protocol_id)
              << ", message_type=" << static_cast<int>(uhdr.message_type) << ", size=" << msg.size()
              << std::endl;

    switch (uhdr.protocol_id) {
        case protocol::ProtocolID::HANDSHAKE: {
            // Charge for receiving the packet
            battery_.consume_rx(payload.size() + protocol::UniversalHeader::kWireSize);

            // Check for unencrypted session reset alert first
            {
                auto hdr_r = protocol::MessageHeader::deserialise(payload);
                if (hdr_r && hdr_r.value().type == protocol::MessageType::Alert) {
                    if (payload.size() >= protocol::MessageHeader::kWireSize) {
                        Bytes body(payload.begin() + protocol::MessageHeader::kWireSize,
                                   payload.end());
                        auto am_r = protocol::AlertMessage::deserialise(body);
                        if (am_r && am_r.value().code == protocol::AlertCode::DecryptionFailed) {
                            std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                      << static_cast<int>(node_id_[1])
                                      << "] Received DecryptionFailed Session Reset Alert from "
                                         "GCS. Renegotiating..."
                                      << std::endl;

                            active_session_id_ = SessionId{};
                            active_peer_id_    = NodeId{};
                            event_bus_->publish(std::string("Session Reset"));
                            start_handshake(0);
                            break;
                        }
                    }
                }
            }

            if (handshake_ && handshake_->state() != protocol::HandshakeState::Complete &&
                handshake_->state() != protocol::HandshakeState::Failed) {
                auto prev_state = handshake_->state();
                auto res        = handshake_->feed_message(payload);
                if (!res) {
                    std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] Error: Handshake feed_message failed: " << res.error().message
                              << std::endl;
                    event_bus_->publish(std::string("Handshake Failed"));
                }

                // If handshake has advanced, consume corresponding cryptographic operations
                // dynamically
                if (res) {
                    auto negotiated_mode = handshake_->get_negotiated_mode();
                    if (prev_state == protocol::HandshakeState::WaitServerHello) {
                        // Initiator received ServerHello: KEM decaps + DSA sign to produce
                        // ClientAuth
                        if (negotiated_mode == protocol::OperatingMode::Classical) {
                            battery_.consume_crypto_x25519_decaps();
                            battery_.consume_crypto_ecdsa_sign();
                        } else if (negotiated_mode == protocol::OperatingMode::Transition ||
                                   negotiated_mode == protocol::OperatingMode::PqcOnly) {
                            battery_.consume_crypto_ml_kem_decaps();
                            battery_.consume_crypto_ml_dsa_sign();
                        } else if (negotiated_mode == protocol::OperatingMode::Hybrid) {
                            battery_.consume_crypto_x25519_decaps();
                            battery_.consume_crypto_ml_kem_decaps();
                            battery_.consume_crypto_ecdsa_sign();
                            battery_.consume_crypto_ml_dsa_sign();
                        }
                    } else if (prev_state == protocol::HandshakeState::WaitServerAuth) {
                        // Initiator received ServerAuth: verify Server's signature
                        if (negotiated_mode == protocol::OperatingMode::Classical) {
                            battery_.consume_crypto_ecdsa_verify();
                        } else if (negotiated_mode == protocol::OperatingMode::Transition ||
                                   negotiated_mode == protocol::OperatingMode::PqcOnly) {
                            battery_.consume_crypto_ml_dsa_verify();
                        } else if (negotiated_mode == protocol::OperatingMode::Hybrid) {
                            battery_.consume_crypto_ecdsa_verify();
                            battery_.consume_crypto_ml_dsa_verify();
                        }
                    }
                }

                if (res && handshake_->state() == protocol::HandshakeState::Complete) {
                    auto hres_r = handshake_->result();
                    if (hres_r) {
                        auto session       = std::move(hres_r.value().session);
                        active_session_id_ = session.id();
                        active_peer_id_    = session.peer_node_id();
                        session_mgr_->add_session(std::move(session), 0);
                        event_bus_->publish(std::string("Handshake Complete"));

                        // Track renegotiation lifecycle metrics
                        session_established_time_ms_ =
                            1000;  // Stand-in or updated dynamic timestamp
                        handshake_count_++;
                        auth_count_++;
                    }
                }
            }
            break;
        }
        case protocol::ProtocolID::TELEMETRY:
        case protocol::ProtocolID::COMMAND: {
            // Charge for receiving bytes
            battery_.consume_rx(payload.size() + protocol::UniversalHeader::kWireSize);

            Bytes decrypted_payload;
            ByteSpan work_payload = payload;

            if (uhdr.message_type == 2) {
                // Decrypt using TreeKEM group key
                auto dec_r = session_mgr_->decrypt_group_broadcast(payload, ByteSpan{}, 0);
                if (dec_r) {
                    decrypted_payload = std::move(dec_r.value());
                    work_payload      = decrypted_payload;

                    // Consume energy for decryption
                    battery_.consume_crypto_symmetric(work_payload.size());
                    auth_count_++;
                    std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] Successfully decrypted TreeKEM Group Broadcast payload."
                              << std::endl;
                } else {
                    std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] Group Decryption failed for payload" << std::endl;
                    return;
                }
            } else if (uhdr.message_type == 1 && active_session_id_ != SessionId{}) {
                auto sess_r = session_mgr_->get_session(active_session_id_, active_peer_id_, 0);
                if (sess_r) {
                    auto dec_r = sess_r.value()->decrypt(payload, ByteSpan{});
                    if (dec_r) {
                        decrypted_payload = std::move(dec_r.value());
                        work_payload      = decrypted_payload;

                        // Consume energy for decryption
                        battery_.consume_crypto_symmetric(work_payload.size());
                        auth_count_++;  // Decryption verified authenticity

                        // Check for custom secure query request (starts with 0xFB, 0xCA)
                        if (decrypted_payload.size() >= 3 &&
                            decrypted_payload[0] == std::byte{0xFB} &&
                            decrypted_payload[1] == std::byte{0xCA}) {
                            std::uint8_t qtype = static_cast<std::uint8_t>(decrypted_payload[2]);
                            std::string path_or_key(
                                reinterpret_cast<const char*>(&decrypted_payload[3]),
                                decrypted_payload.size() - 3);

                            std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                      << static_cast<int>(node_id_[1])
                                      << "] Received Secure Query Request. Type=" << (int)qtype
                                      << " Path=" << path_or_key << std::endl;

                            // Process query
                            std::string response = "Query type not recognized";
                            if (qtype == 1) {  // Flight logs
                                response =
                                    "FLIGHT LOGS: Alt=120m Yaw=0.45rad Lat=28.6139 Lon=77.2090 "
                                    "CPU=18% Memory=40MB Session=Active";
                            } else if (qtype == 2) {  // ACPE Policy State
                                response =
                                    "ACPE STATE: mode=Hybrid profile=Standard battery=98.2% "
                                    "override=false rssi=-70.4dBm sinr=15.4dB";
                            } else if (qtype == 3) {  // Dynamic Storage Snapshot
                                response =
                                    "STORAGE SNAPSHOT: /home/pi/logs (12.4MB) /home/pi/bin (8.9MB) "
                                    "/tmp (1.2MB) Free=14.5GB";
                            } else if (qtype == 4) {  // Custom Config File / Read file
                                response =
                                    "CONFIG FILE: { \"uav_id\": \"0:1\", \"telemetry_rate_hz\": 2, "
                                    "\"pqc_enabled\": true, \"treekem_epoch\": 4 }";
                            } else if (qtype == 5) {  // List files in directory
                                // Scan the given directory and return real file metadata
                                std::string dir_path = path_or_key.empty() ? "." : path_or_key;

                                // Enforce sandbox validation against the configured query root
                                if (!is_path_safe(dir_path, get_query_root())) {
                                    response = "ERROR:Access Denied (Sandbox Traversal)";
                                } else {
                                    std::string file_list;
                                    DIR* dir = opendir(dir_path.c_str());
                                    if (dir) {
                                        struct dirent* entry;
                                        int file_count = 0;
                                        while ((entry = readdir(dir)) != nullptr) {
                                            if (entry->d_name[0] == '.')
                                                continue;  // skip hidden
                                            if (++file_count > 100)
                                                break;     // Limit list size to 100 entries

                                            std::string full_path = dir_path + "/" + entry->d_name;
                                            struct stat st;
                                            if (stat(full_path.c_str(), &st) != 0)
                                                continue;
                                            if (S_ISDIR(st.st_mode))
                                                continue;  // skip subdirs

                                            // Determine file type from extension
                                            std::string name = entry->d_name;
                                            std::string ext;
                                            auto dot = name.rfind('.');
                                            if (dot != std::string::npos)
                                                ext = name.substr(dot + 1);
                                            std::string ftype = "file";
                                            if (ext == "mp4" || ext == "avi" || ext == "mkv" ||
                                                ext == "mov")
                                                ftype = "video";
                                            else if (ext == "jpg" || ext == "jpeg" ||
                                                     ext == "png" || ext == "bmp")
                                                ftype = "image";
                                            else if (ext == "log" || ext == "txt" || ext == "csv")
                                                ftype = "log";
                                            else if (ext == "bin" || ext == "dat")
                                                ftype = "binary";
                                            else if (ext == "json")
                                                ftype = "config";

                                            if (!file_list.empty())
                                                file_list += "|";
                                            file_list +=
                                                "name=" + name + ",size=" +
                                                std::to_string(static_cast<long long>(st.st_size)) +
                                                ",type=" + ftype + ",path=" + full_path;
                                        }
                                        closedir(dir);
                                        if (file_list.empty())
                                            file_list = "EMPTY_DIR";
                                    } else {
                                        file_list = "ERROR:Cannot open directory: " + dir_path;
                                    }
                                    response = "FILE_LIST:" + file_list;
                                }
                            } else if (qtype ==
                                       6) {  // File pull/download request over secure channel
                                std::string filepath = path_or_key;
                                std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                          << static_cast<int>(node_id_[1])
                                          << "] Secure file retrieval request for: " << filepath
                                          << std::endl;

                                // Enforce sandbox validation against the configured query root
                                if (!is_path_safe(filepath, get_query_root())) {
                                    response = "ERROR:Access Denied (Sandbox Traversal)";
                                    std::cerr << "[UAV] Traversal check failed: " << filepath
                                              << std::endl;

                                    // Send immediate error query response
                                    Bytes resp_payload;
                                    resp_payload.push_back(std::byte{0xFB});
                                    resp_payload.push_back(std::byte{0xCB});
                                    resp_payload.push_back(static_cast<std::byte>(qtype));
                                    resp_payload.push_back(node_id_[0]);
                                    resp_payload.push_back(node_id_[1]);
                                    resp_payload.insert(
                                        resp_payload.end(),
                                        reinterpret_cast<const std::byte*>(response.data()),
                                        reinterpret_cast<const std::byte*>(response.data()) +
                                            response.size());
                                    send_telemetry(resp_payload);
                                } else {
                                    // Validate file size limit (50 MB)
                                    struct stat st;
                                    if (stat(filepath.c_str(), &st) == 0 &&
                                        st.st_size > 50 * 1024 * 1024) {
                                        response = "ERROR:File exceeds maximum size limit (50MB)";
                                        Bytes resp_payload;
                                        resp_payload.push_back(std::byte{0xFB});
                                        resp_payload.push_back(std::byte{0xCB});
                                        resp_payload.push_back(static_cast<std::byte>(qtype));
                                        resp_payload.push_back(node_id_[0]);
                                        resp_payload.push_back(node_id_[1]);
                                        resp_payload.insert(
                                            resp_payload.end(),
                                            reinterpret_cast<const std::byte*>(response.data()),
                                            reinterpret_cast<const std::byte*>(response.data()) +
                                                response.size());
                                        send_telemetry(resp_payload);
                                    } else {
                                        // Spin background thread to transmit file in chunked
                                        // telemetry packets
                                        std::thread([this, filepath, qtype]() {
                                            std::ifstream infile(filepath, std::ios::binary);
                                            if (!infile.good()) {
                                                std::cout << "[UAV] File open failed: " << filepath
                                                          << std::endl;
                                                return;
                                            }

                                            std::vector<char> buffer(1024);
                                            int chunk_index                 = 0;
                                            std::streamsize last_bytes_read = 0;

                                            while (infile.read(buffer.data(), buffer.size()) ||
                                                   infile.gcount() > 0) {
                                                std::streamsize bytes_read = infile.gcount();
                                                last_bytes_read            = bytes_read;
                                                Bytes chunk(bytes_read);
                                                std::memcpy(
                                                    chunk.data(), buffer.data(), bytes_read);

                                                // Format: [FILE_TRANSFER_MAGIC (2 bytes: 0xFA,
                                                // 0xCE)] [chunk_index (4 bytes)] [data]
                                                Bytes wrapped_chunk;
                                                wrapped_chunk.push_back(std::byte{0xFA});
                                                wrapped_chunk.push_back(std::byte{0xCE});
                                                uint32_t c_idx = static_cast<uint32_t>(chunk_index);
                                                uint8_t idx_buf[4];
                                                std::memcpy(idx_buf, &c_idx, 4);
                                                wrapped_chunk.insert(
                                                    wrapped_chunk.end(),
                                                    reinterpret_cast<const std::byte*>(idx_buf),
                                                    reinterpret_cast<const std::byte*>(idx_buf) +
                                                        4);
                                                wrapped_chunk.insert(wrapped_chunk.end(),
                                                                     chunk.begin(),
                                                                     chunk.end());

                                                (void)this->send_telemetry(wrapped_chunk);
                                                chunk_index++;
                                                std::this_thread::sleep_for(
                                                    std::chrono::milliseconds(20));  // Flow control
                                            }

                                            // Handle exact multiples of 1024 by sending EOF packet
                                            if (last_bytes_read == 1024) {
                                                Bytes wrapped_eof;
                                                wrapped_eof.push_back(std::byte{0xFA});
                                                wrapped_eof.push_back(std::byte{0xCE});
                                                uint32_t c_idx = static_cast<uint32_t>(chunk_index);
                                                uint8_t idx_buf[4];
                                                std::memcpy(idx_buf, &c_idx, 4);
                                                wrapped_eof.insert(
                                                    wrapped_eof.end(),
                                                    reinterpret_cast<const std::byte*>(idx_buf),
                                                    reinterpret_cast<const std::byte*>(idx_buf) +
                                                        4);
                                                (void)this->send_telemetry(wrapped_eof);
                                            }
                                        }).detach();
                                    }
                                }
                                return;  // background thread handles telemetry streaming
                            }

                            // Build query response payload (starts with 0xFB, 0xCB)
                            Bytes resp_payload;
                            resp_payload.push_back(std::byte{0xFB});
                            resp_payload.push_back(std::byte{0xCB});
                            resp_payload.push_back(static_cast<std::byte>(qtype));
                            resp_payload.push_back(node_id_[0]);
                            resp_payload.push_back(node_id_[1]);
                            resp_payload.insert(
                                resp_payload.end(),
                                reinterpret_cast<const std::byte*>(response.data()),
                                reinterpret_cast<const std::byte*>(response.data()) +
                                    response.size());

                            // Send query reply
                            send_telemetry(resp_payload);
                        }
                    } else {
                        std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                  << static_cast<int>(node_id_[1])
                                  << "] Decryption failed for payload" << std::endl;
                        return;
                    }
                } else {
                    return;
                }
            }

            // Publish raw decrypted stream for loopback sniffing
            event_bus_->publish(
                DecryptedMavlinkStream{Bytes(work_payload.begin(), work_payload.end())});

            // Parse MAVLink stream
            auto frames = mavlink_parser_.feed(
                reinterpret_cast<const uint8_t*>(work_payload.data()), work_payload.size());
            for (const auto& frame : frames) {
                event_bus_->publish(frame.payload);

                if (frame.header.msgid == mavlink::CommandLong::MSG_ID) {
                    mavlink::CommandLong cmd;
                    std::memcpy(&cmd, frame.payload.data(), sizeof(cmd));
                    std::cout << "[MAVLINK UAV] Received COMMAND_LONG: command=" << cmd.command
                              << ", target_sys=" << (int)cmd.target_system
                              << ", target_comp=" << (int)cmd.target_component << std::endl;
                    if (cmd.command == 50001) {
                        handle_classical_mode_decision(cmd);
                    }
                } else {
                    std::cout << "[MAVLINK UAV] Received MAVLink message: msgid="
                              << frame.header.msgid << std::endl;
                }
            }

            if (frames.empty()) {
                event_bus_->publish(Bytes(work_payload.begin(), work_payload.end()));
            }
            break;
        }
        case protocol::ProtocolID::TREEKEM: {
            battery_.consume_rx(payload.size() + protocol::UniversalHeader::kWireSize);
            battery_.consume_treekem();
            treekem_rekeys_++;

            if (!payload.empty() && payload[0] == std::byte{0x7B}) {
                // Serialized Tree State JSON from GCS to sync swarm membership
                auto res = treekem_ctrl_->deserialize_tree(payload);
                if (res) {
                    std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] Successfully synchronized TreeKEM membership/public state. "
                                 "Swarm size: "
                              << treekem_ctrl_->get_membership().size() << std::endl;
                } else {
                    std::cerr << "[UAV] Failed to deserialize GCS TreeKEM state: "
                              << res.error().message << std::endl;
                }
            } else {
                // Deserialize TreeKEM GroupKeyUpdate
                auto deser_r = group::deserialize_group_key_update(payload);
                if (deser_r) {
                    auto gk_r = treekem_ctrl_->process_group_update(
                        deser_r.value(), node_id_, treekem_priv_key_);
                    if (gk_r) {
                        session_mgr_->set_group_key(std::move(gk_r.value()));
                        std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                  << static_cast<int>(node_id_[1])
                                  << "] Successfully processed TreeKEM update. Installed group key "
                                     "for epoch "
                                  << treekem_ctrl_->get_epoch() << std::endl;
                    } else {
                        std::cerr << "[UAV] TreeKEM process_group_update failed: "
                                  << gk_r.error().message << std::endl;
                    }
                } else {
                    std::cerr << "[UAV] Failed to deserialize GroupKeyUpdate" << std::endl;
                }
            }

            event_bus_->publish(payload);
            break;
        }
        case protocol::ProtocolID::HEARTBEAT: {
            event_bus_->publish(payload);
            break;
        }
        case protocol::ProtocolID::D2D: {
            if (uhdr.message_type ==
                static_cast<std::uint8_t>(protocol::MessageType::D2DSessionResp)) {
                // Decrypt GCS key distribution response using pairwise GCS session
                Bytes dec_body = payload;
                auto sess_r    = session_mgr_->get_session(active_session_id_, active_peer_id_, 0);
                if (sess_r) {
                    auto d_res = sess_r.value()->decrypt(payload, ByteSpan{});
                    if (d_res) {
                        dec_body = d_res.value();
                    }
                }

                auto resp_r = protocol::D2DSessionRespPayload::deserialize(dec_body);
                if (resp_r) {
                    const auto& resp = resp_r.value();
                    session::D2DSession sess;
                    sess.session_id    = resp.session_id;
                    sess.local_node_id = node_id_;
                    sess.peer_node_id  = (resp.initiator_node_id == node_id_)
                                             ? resp.target_node_id
                                             : resp.initiator_node_id;
                    sess.peer_ip       = resp.target_ip;
                    sess.peer_port     = resp.target_port;
                    sess.session_key   = SecureBytes(
                        Bytes(resp.session_key.bytes().begin(), resp.session_key.bytes().end()));
                    sess.lifetime_seconds           = resp.lifetime_seconds;
                    sess.inactivity_timeout_seconds = resp.inactivity_timeout_seconds;
                    sess.created_at                 = static_cast<Timestamp>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                    sess.expires_at = sess.created_at +
                                      (static_cast<std::uint64_t>(resp.lifetime_seconds) * 1000);
                    sess.last_active_at = sess.created_at;
                    sess.is_initiator   = (resp.initiator_node_id == node_id_);

                    d2d_manager_.add_session(std::move(sess));
                    std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] Successfully established Ephemeral D2D session with Peer "
                              << static_cast<int>(sess.peer_node_id[0]) << ":"
                              << static_cast<int>(sess.peer_node_id[1]) << " (" << sess.peer_ip
                              << ":" << sess.peer_port << ")" << std::endl;
                }
            } else if (uhdr.message_type ==
                       static_cast<std::uint8_t>(protocol::MessageType::D2DDirectHello)) {
                auto hello_r = protocol::D2DDirectHelloPayload::deserialize(payload);
                if (hello_r) {
                    ensure_d2d_handshake_manager();
                    std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] D2DDirectHello deserialized: kem_public_key size = "
                              << hello_r.value().kem_public_key.size()
                              << ", cert size = " << hello_r.value().initiator_cert.size()
                              << std::endl;
                    Timestamp now_ms = static_cast<Timestamp>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                    auto res = d2d_handshake_mgr_->process_hello(hello_r.value(), now_ms);
                    if (res) {
                        auto [resp_payload, d2d_sess] = std::move(res.value());

                        // Populate peer_ip and peer_port for local/static routing
                        d2d_sess.peer_ip = "127.0.0.1";
                        d2d_sess.peer_port =
                            28002 + static_cast<int>(hello_r.value().initiator_id[1]);

                        d2d_manager_.add_session(std::move(d2d_sess));

                        Bytes body = resp_payload.serialize();
                        Bytes wire = protocol::wrap_packet(
                            protocol::ProtocolID::D2D,
                            body,
                            static_cast<std::uint8_t>(protocol::MessageType::D2DDirectResp));
                        network_mgr_->send_message_to(hello_r.value().initiator_id, wire);

                        std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                  << static_cast<int>(node_id_[1])
                                  << "] Processed D2DDirectHello and established session with Peer "
                                  << static_cast<int>(hello_r.value().initiator_id[0]) << ":"
                                  << static_cast<int>(hello_r.value().initiator_id[1]) << std::endl;
                    } else {
                        std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                  << static_cast<int>(node_id_[1])
                                  << "] D2DDirectHello processing failed: " << res.error().message
                                  << std::endl;
                    }
                } else {
                    std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] D2DDirectHello deserialization failed: "
                              << hello_r.error().message << std::endl;
                }
            } else if (uhdr.message_type ==
                       static_cast<std::uint8_t>(protocol::MessageType::D2DDirectResp)) {
                auto resp_r = protocol::D2DDirectRespPayload::deserialize(payload);
                if (resp_r) {
                    ensure_d2d_handshake_manager();
                    Timestamp now_ms = static_cast<Timestamp>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                    auto res = d2d_handshake_mgr_->process_resp(resp_r.value(), now_ms);
                    if (res) {
                        auto d2d_sess = std::move(res.value());

                        // Populate peer_ip and peer_port for local/static routing
                        d2d_sess.peer_ip   = "127.0.0.1";
                        d2d_sess.peer_port = 28002 + static_cast<int>(resp_r.value().target_id[1]);

                        d2d_manager_.add_session(std::move(d2d_sess));
                        std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                  << static_cast<int>(node_id_[1])
                                  << "] Processed D2DDirectResp and completed session with Peer "
                                  << static_cast<int>(resp_r.value().target_id[0]) << ":"
                                  << static_cast<int>(resp_r.value().target_id[1]) << std::endl;
                    } else {
                        std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                  << static_cast<int>(node_id_[1])
                                  << "] D2DDirectResp processing failed: " << res.error().message
                                  << std::endl;
                    }
                } else {
                    std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] D2DDirectResp deserialization failed: "
                              << resp_r.error().message << std::endl;
                }
            } else if (uhdr.message_type ==
                       static_cast<std::uint8_t>(protocol::MessageType::D2DData)) {
                // Direct encrypted peer D2D data
                Timestamp now_ms =
                    static_cast<Timestamp>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
                auto dec_res = d2d_manager_.decrypt_payload(uhdr.session_id, payload, now_ms);
                if (dec_res) {
                    std::string decrypted_str(reinterpret_cast<const char*>(dec_res.value().data()),
                                              dec_res.value().size());
                    std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] Decrypted direct D2D message: \"" << decrypted_str << "\""
                              << std::endl;
                    event_bus_->publish(dec_res.value());
                } else {
                    std::cerr << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                              << static_cast<int>(node_id_[1])
                              << "] D2D Decryption failed: " << dec_res.error().message
                              << std::endl;
                    // Send an unencrypted Alert back to the source node requesting D2D session
                    // reset!
                    protocol::AlertMessage am{
                        .level       = protocol::AlertLevel::Fatal,
                        .code        = protocol::AlertCode::DecryptionFailed,
                        .description = "D2D Decryption Failed - Session Reset Required"};
                    Bytes body = am.serialise();
                    protocol::MessageHeader hdr{.type   = protocol::MessageType::Alert,
                                                .length = static_cast<std::uint16_t>(body.size()),
                                                .session_id      = uhdr.session_id,
                                                .sequence_number = 0xFFFF};
                    Bytes wire = hdr.serialise();
                    wire.insert(wire.end(), body.begin(), body.end());

                    Bytes packet = protocol::wrap_packet(
                        protocol::ProtocolID::D2D,
                        wire,
                        static_cast<std::uint8_t>(protocol::MessageType::Alert),
                        uhdr.session_id);
                    (void)network_mgr_->send_message_to(src_id, packet);
                }
            } else if (uhdr.message_type ==
                       static_cast<std::uint8_t>(protocol::MessageType::Alert)) {
                auto hdr_r = protocol::MessageHeader::deserialise(payload);
                if (hdr_r) {
                    Bytes body(payload.begin() + protocol::MessageHeader::kWireSize, payload.end());
                    auto am_r = protocol::AlertMessage::deserialise(body);
                    if (am_r && am_r.value().code == protocol::AlertCode::DecryptionFailed) {
                        std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                                  << static_cast<int>(node_id_[1])
                                  << "] Received D2D DecryptionFailed Alert from Peer. Resetting "
                                     "D2D session and renegotiating..."
                                  << std::endl;

                        // Terminate the local session
                        d2d_manager_.terminate_session(uhdr.session_id);

                        // Renegotiate handshake immediately on-demand
                        ensure_d2d_handshake_manager();
                        (void)initiate_d2d_handshake(src_id);
                    }
                }
            }
            break;
        }
        case protocol::ProtocolID::VIDEO: {
            // UAVs do not receive video stream, ignore it.
            break;
        }
    }
}

double Uav::get_session_lifetime_sec(Timestamp now_ms) const noexcept {
    if (session_established_time_ms_ == 0 || now_ms <= session_established_time_ms_) {
        return 0.0;
    }
    return static_cast<double>(now_ms - session_established_time_ms_) / 1000.0;
}

double Uav::get_telemetry_interval_ms() const noexcept {
    if (shutdown_initiated_ || battery_level_ <= 0.0) {
        return 999999.0;  // Disabled
    }

    double base = telemetry_interval_ms_;

    if (battery_level_ < 10.0) {
        return 10000.0;                       // 10s for emergency mode
    } else if (battery_level_ < 20.0) {
        return 5000.0;                        // 5s for emergency profile
    } else if (battery_level_ < 40.0) {
        return std::max(base * 5.0, 5000.0);  // Prioritize control traffic, sparse telemetry
    } else if (battery_level_ < 70.0) {
        return base * 2.0;                    // Reduce unnecessary transmissions
    }
    return base;
}

void Uav::set_link_stats(double rssi, double sinr, double packet_loss, double latency_ms) noexcept {
    link_rssi_        = rssi;
    link_sinr_        = sinr;
    link_packet_loss_ = packet_loss;
    link_latency_ms_  = latency_ms;
}

std::string Uav::get_active_session_id_hex() const noexcept {
    if (active_session_id_ == SessionId{}) {
        return "None";
    }
    std::ostringstream ss;
    for (auto b : active_session_id_) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

void Uav::approve_classical_mode(std::uint32_t operator_id) {
    mavlink::CommandLong cmd{};
    cmd.command = 50001;
    cmd.param1  = 1.0f;  // Approve
    cmd.param2  = static_cast<float>(operator_id);
    cmd.param3  = 3.0f;  // Critical battery / availability recovery
    handle_classical_mode_decision(cmd);
}

void Uav::handle_classical_mode_decision(const mavlink::CommandLong& cmd) {
    float decision       = cmd.param1;
    uint32_t operator_id = static_cast<uint32_t>(cmd.param2);
    std::string reason   = "Operator decision";
    if (cmd.param3 == 1.0f)
        reason = "Severe link degradation";
    else if (cmd.param3 == 2.0f)
        reason = "High packet loss";
    else if (cmd.param3 == 3.0f)
        reason = "Critical battery recommendation";

    std::string prev_mode =
        std::string(protocol::to_string(config_mgr_->get_config().offered_modes.empty()
                                            ? protocol::OperatingMode::Hybrid
                                            : config_mgr_->get_config().offered_modes[0]));

    if (decision == 1.0f) {  // Approve
        std::uint64_t ts = std::chrono::system_clock::now().time_since_epoch().count();
        std::cout << "[DOWNGRADE LOG] Timestamp=" << ts << " OperatorID=" << operator_id
                  << " Mission=" << get_mission_name() << " Reason=\"" << reason << "\""
                  << " PreviousMode=" << prev_mode << " NewMode=Classical" << std::endl;

        classical_approved_             = true;
        waiting_for_classical_approval_ = false;

        auto& config         = const_cast<AppConfig&>(config_mgr_->get_config());
        config.offered_modes = {protocol::OperatingMode::Classical};

        start_handshake(0);
    } else if (decision == 2.0f) {  // Reject
        std::uint64_t ts = std::chrono::system_clock::now().time_since_epoch().count();
        std::cout << "[CLASSICAL REJECTED] Timestamp=" << ts << " OperatorID=" << operator_id
                  << " Mission=" << get_mission_name() << " Reason=\"" << reason << "\""
                  << " PreviousMode=" << prev_mode << " Decision=Rejected" << std::endl;
        waiting_for_classical_approval_ = false;
        classical_approved_             = false;
    } else if (decision == 3.0f) {  // Abort Mission
        std::uint64_t ts = std::chrono::system_clock::now().time_since_epoch().count();
        std::cout << "[MISSION ABORTED] Timestamp=" << ts << " OperatorID=" << operator_id
                  << " Mission=" << get_mission_name() << " Reason=\"Abort Command\"" << std::endl;
        mission_.speed_m_s              = 0.0;
        waiting_for_classical_approval_ = false;
    } else if (decision == 4.0f) {  // Return to Base
        std::uint64_t ts = std::chrono::system_clock::now().time_since_epoch().count();
        std::cout << "[RETURN TO BASE] Timestamp=" << ts << " OperatorID=" << operator_id
                  << " Mission=" << get_mission_name() << " Reason=\"Return to Base Command\""
                  << std::endl;
        mission_.speed_m_s              = 5.0;
        waiting_for_classical_approval_ = false;
    }
}

void Uav::set_mission(const UavMission& mission) noexcept {
    mission_ = mission;
    // Dynamically trigger ACPE re-evaluation!
    set_battery_level(battery_level_, last_battery_update_ms_);
}

void Uav::set_treekem_private_key(crypto::KemPrivateKey priv_key) {
    treekem_priv_key_ = std::move(priv_key);
}

VoidResult Uav::request_d2d_session(const NodeId& target_node_id, std::uint32_t lifetime_sec) {
    protocol::D2DSessionReqPayload req;
    req.initiator_node_id          = node_id_;
    req.target_node_id             = target_node_id;
    req.requested_lifetime_seconds = lifetime_sec;
    req.traffic_reason             = "On-demand direct D2D telemetry/data";

    Bytes body = req.serialize();

    auto sess_r = session_mgr_->get_session(active_session_id_, active_peer_id_, 0);
    if (sess_r) {
        auto enc_r = sess_r.value()->encrypt(body, ByteSpan{});
        if (enc_r) {
            body = enc_r.value();
        }
    }

    Bytes wire =
        protocol::wrap_packet(protocol::ProtocolID::D2D,
                              body,
                              static_cast<std::uint8_t>(protocol::MessageType::D2DSessionReq));
    return network_mgr_->send_message(wire);
}

Result<Bytes> Uav::send_d2d_payload(const NodeId& target_node_id,
                                    ByteSpan payload,
                                    Timestamp now_ms) {
    auto sess = d2d_manager_.find_session_by_peer(target_node_id);
    if (!sess) {
        std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":"
                  << static_cast<int>(node_id_[1])
                  << "] D2D session not found for Peer. Initiating on-demand P2P handshake..."
                  << std::endl;
        ensure_d2d_handshake_manager();
        auto res = initiate_d2d_handshake(target_node_id);
        if (!res) {
            return err<Bytes>(res.error().code, res.error().message);
        }
        return err<Bytes>(ErrorCode::SessionNotFound, "Initiating on-demand D2D handshake");
    }

    auto enc_r = d2d_manager_.encrypt_payload(sess->session_id, payload, now_ms);
    if (!enc_r) {
        return enc_r.error();
    }

    Bytes wire = protocol::wrap_packet(protocol::ProtocolID::D2D,
                                       enc_r.value(),
                                       static_cast<std::uint8_t>(protocol::MessageType::D2DData),
                                       sess->session_id);
    network_mgr_->send_message_to(target_node_id, wire);
    return enc_r.value();
}

VoidResult Uav::terminate_d2d_session(const NodeId& target_node_id) {
    auto sess = d2d_manager_.find_session_by_peer(target_node_id);
    if (sess) {
        d2d_manager_.terminate_session(sess->session_id);
    }
    return ok();
}

void Uav::ensure_d2d_handshake_manager() {
    if (!d2d_handshake_mgr_) {
        auto provider                     = std::make_shared<crypto::DefaultCryptoProvider>();
        std::shared_ptr<crypto::IKem> kem = provider->create_hybrid_kem();
        std::shared_ptr<crypto::IDsa> dsa = provider->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
        d2d_handshake_mgr_ =
            std::make_unique<protocol::D2DHandshakeManager>(node_id_, kem, dsa, cert_);
    }
}

VoidResult Uav::initiate_d2d_handshake(const NodeId& target_node_id) {
    ensure_d2d_handshake_manager();
    auto hello_res = d2d_handshake_mgr_->initiate_handshake(target_node_id);
    if (!hello_res) {
        return err(hello_res.error().code, hello_res.error().message);
    }

    Bytes body = hello_res.value().serialize();
    Bytes wire =
        protocol::wrap_packet(protocol::ProtocolID::D2D,
                              body,
                              static_cast<std::uint8_t>(protocol::MessageType::D2DDirectHello));
    std::cout << "[UAV-" << static_cast<int>(node_id_[0]) << ":" << static_cast<int>(node_id_[1])
              << "] initiate_d2d_handshake: sending D2DDirectHello to UAV-"
              << static_cast<int>(target_node_id[1]) << " size=" << wire.size()
              << " body_size=" << body.size() << std::endl;
    return network_mgr_->send_message_to(target_node_id, wire);
}

}  // namespace uav_pqc::app
