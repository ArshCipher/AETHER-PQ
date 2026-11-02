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
#include "uav_pqc/protocol/d2d_handshake.hpp"

#include "uav_pqc/session/d2d_manager.hpp"
#include "uav_pqc/protocol/d2d_messages.hpp"

#include <memory>
#include <string>
#include <vector>

namespace uav_pqc::app {

enum class UavMissionType : std::uint8_t {
    Surveillance = 0,
    Patrol       = 1,
    Delivery     = 2,
    SearchRescue = 3,
    Formation    = 4
};


struct UavMission {
    UavMissionType type = UavMissionType::Surveillance;
    double criticality = 6.0;
    double speed_m_s = 10.0;
    double target_altitude = 50.0;

    // Mission-aware policy fields
    protocol::OperatingMode default_operating_mode = protocol::OperatingMode::Hybrid;
    policy::CryptographicProfile default_crypto_profile = policy::CryptographicProfile::Standard;
    double telemetry_interval_sec = 1.0;
    std::uint32_t payload_size = 800;
    std::string preferred_cipher_suite = "MLKEM768-MLDSA65-AES256GCM";
    double treekem_rekey_interval_sec = 30.0;
    std::uint32_t session_lifetime_sec = 1200;
    double battery_consumption_multiplier = 1.0;
    double communication_priority = 5.0;
    double neighbor_sync_rate = 1.0;
    bool video_streaming_enabled = true;
};

struct BatteryModel {
    double total_capacity_joules = 15000.0; // small capacity for quick draining in simulation
    double remaining_energy_joules = 15000.0;
    
    // Constant power coefficients (Watts)
    double p_hover = 200.0;
    double c_drag = 0.1; // flight power = p_hover + c_drag * velocity^3
    double p_climb = 50.0; // Watt per m/s climb rate
    double p_descend = -20.0; // saves energy during descend
    
    // Comm energy coefficients (Joules per byte)
    double e_tx_per_byte = 0.005;
    double e_rx_per_byte = 0.003;
    
    // Cryptographic energy coefficients (Joules per operation)
    double e_ml_kem_encaps = 0.5;
    double e_ml_kem_decaps = 0.6;
    double e_ml_dsa_sign = 1.0;
    double e_ml_dsa_verify = 0.8;
    double e_symmetric_per_byte = 0.0001; // AES-GCM / ChaCha20
    double e_treekem_operation = 1.5;
    double p_cpu_idle = 2.0; // Watts CPU idle consumption

    // New coefficients for Classical / keygen operations
    double e_x25519_keygen = 0.08;
    double e_x25519_encaps = 0.12;
    double e_x25519_decaps = 0.12;
    double e_ecdsa_sign = 0.15;
    double e_ecdsa_verify = 0.20;
    double e_ml_kem_keygen = 0.35;
    double e_ml_dsa_keygen = 0.50;

    // Subsystem energy tracking (Joules)
    double energy_flight = 0.0;
    double energy_radio_tx = 0.0;
    double energy_radio_rx = 0.0;
    double energy_cpu_idle = 0.0;
    double energy_crypto_kem = 0.0;
    double energy_crypto_dsa = 0.0;
    double energy_crypto_sym = 0.0;
    double energy_treekem = 0.0;

    void consume_cpu_idle(double dt_seconds) {
        double diff = p_cpu_idle * dt_seconds;
        remaining_energy_joules -= diff;
        energy_cpu_idle += diff;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    double get_percent() const {
        return (remaining_energy_joules / total_capacity_joules) * 100.0;
    }

    void consume_idle(double dt_seconds, double speed, double climb_rate) {
        double p_flight = p_hover + c_drag * (speed * speed * speed);
        double p_alt = climb_rate > 0.0 ? p_climb * climb_rate : p_descend * climb_rate;
        double total_p = p_flight + p_alt;
        if (total_p < 50.0) total_p = 50.0; // minimum power draw
        double diff = total_p * dt_seconds;
        remaining_energy_joules -= diff;
        energy_flight += diff;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_tx(size_t bytes) {
        double diff = bytes * e_tx_per_byte;
        remaining_energy_joules -= diff;
        energy_radio_tx += diff;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_rx(size_t bytes) {
        double diff = bytes * e_rx_per_byte;
        remaining_energy_joules -= diff;
        energy_radio_rx += diff;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_kem_encaps() {
        remaining_energy_joules -= e_ml_kem_encaps;
        energy_crypto_kem += e_ml_kem_encaps;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_kem_decaps() {
        remaining_energy_joules -= e_ml_kem_decaps;
        energy_crypto_kem += e_ml_kem_decaps;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_dsa_sign() {
        remaining_energy_joules -= e_ml_dsa_sign;
        energy_crypto_dsa += e_ml_dsa_sign;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_dsa_verify() {
        remaining_energy_joules -= e_ml_dsa_verify;
        energy_crypto_dsa += e_ml_dsa_verify;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_symmetric(size_t bytes) {
        double diff = bytes * e_symmetric_per_byte;
        remaining_energy_joules -= diff;
        energy_crypto_sym += diff;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_treekem() {
        remaining_energy_joules -= e_treekem_operation;
        energy_treekem += e_treekem_operation;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    // Classical and Keygen operations
    void consume_crypto_x25519_keygen() {
        remaining_energy_joules -= e_x25519_keygen;
        energy_crypto_kem += e_x25519_keygen;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_x25519_encaps() {
        remaining_energy_joules -= e_x25519_encaps;
        energy_crypto_kem += e_x25519_encaps;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_x25519_decaps() {
        remaining_energy_joules -= e_x25519_decaps;
        energy_crypto_kem += e_x25519_decaps;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_ecdsa_sign() {
        remaining_energy_joules -= e_ecdsa_sign;
        energy_crypto_dsa += e_ecdsa_sign;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_ecdsa_verify() {
        remaining_energy_joules -= e_ecdsa_verify;
        energy_crypto_dsa += e_ecdsa_verify;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_ml_kem_keygen() {
        remaining_energy_joules -= e_ml_kem_keygen;
        energy_crypto_kem += e_ml_kem_keygen;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_ml_dsa_keygen() {
        remaining_energy_joules -= e_ml_dsa_keygen;
        energy_crypto_dsa += e_ml_dsa_keygen;
        if (remaining_energy_joules < 0.0) remaining_energy_joules = 0.0;
    }

    void consume_crypto_ml_kem_encaps() { consume_crypto_kem_encaps(); }
    void consume_crypto_ml_kem_decaps() { consume_crypto_kem_decaps(); }
    void consume_crypto_ml_dsa_sign() { consume_crypto_dsa_sign(); }
    void consume_crypto_ml_dsa_verify() { consume_crypto_dsa_verify(); }
};

/**
 * @brief Abstract UAV interface.
 */
class IUav {
public:
    IUav() = default;
    virtual ~IUav() = default;

    IUav(const IUav&) = delete;
    IUav& operator=(const IUav&) = delete;
    IUav(IUav&&) noexcept = default;
    IUav& operator=(IUav&&) noexcept = default;

    virtual VoidResult initialize(const std::string& config_str) = 0;
    virtual VoidResult start_handshake(Timestamp now_ms) = 0;
    virtual VoidResult receive_packet(ByteSpan packet, Timestamp now_ms) = 0;
    virtual VoidResult send_telemetry(ByteSpan payload, Timestamp now_ms = 0) = 0;
    virtual VoidResult send_video_frame(ByteSpan jpeg_bytes, uint16_t width, uint16_t height, uint32_t frame_seq, Timestamp now_ms) = 0;
    virtual void set_battery_level(double percent, Timestamp now_ms) = 0;
    virtual double get_battery_level() const noexcept = 0;
    virtual void update_battery(Timestamp now_ms, double speed_m_s, double climb_rate) = 0;
    virtual double get_remaining_energy_joules() const noexcept = 0;
    virtual std::string get_mission_name() const noexcept = 0;
    virtual VoidResult initiate_d2d_handshake(const NodeId& target_node_id) = 0;
    
    virtual const NodeId& get_node_id() const noexcept = 0;
    virtual const std::shared_ptr<ISessionManager>& get_session_manager() const noexcept = 0;

    // ── Metrics & Lifecycle Getters ──────────────────────────────────────────
    virtual uint32_t get_packets_sent() const noexcept = 0;
    virtual uint32_t get_packets_received() const noexcept = 0;
    virtual uint32_t get_handshake_count() const noexcept = 0;
    virtual protocol::HandshakeState get_handshake_state() const noexcept = 0;
    virtual uint32_t get_auth_count() const noexcept = 0;
    virtual uint32_t get_treekem_rekeys() const noexcept = 0;
    virtual double get_session_lifetime_sec(Timestamp now_ms) const noexcept = 0;
    virtual double get_telemetry_interval_ms() const noexcept = 0;
    virtual bool is_emergency() const noexcept = 0;
    virtual bool is_shutdown() const noexcept = 0;
    virtual void set_link_stats(double rssi, double sinr, double packet_loss, double latency_ms) noexcept = 0;
    virtual void trigger_treekem_rekey() noexcept = 0;
    virtual void set_threat_level(policy::ThreatLevel level) noexcept = 0;
    virtual double get_energy_consumed() const noexcept = 0;
    virtual std::string get_active_session_id_hex() const noexcept = 0;
    virtual double get_treekem_rekey_interval_sec() const noexcept = 0;
    virtual std::uint32_t get_payload_size() const noexcept = 0;
    virtual void set_mission(const UavMission& mission) noexcept = 0;
    virtual const UavMission& get_mission() const noexcept = 0;
    virtual bool is_waiting_for_classical_approval() const noexcept = 0;
    virtual bool is_classical_approved() const noexcept = 0;
    virtual void approve_classical_mode(std::uint32_t operator_id) = 0;
    virtual policy::FsmState get_fsm_state() const noexcept = 0;
    virtual double get_energy_flight() const noexcept = 0;
    virtual double get_energy_radio_tx() const noexcept = 0;
    virtual double get_energy_radio_rx() const noexcept = 0;
    virtual double get_energy_cpu_idle() const noexcept = 0;
    virtual double get_energy_crypto_kem() const noexcept = 0;
    virtual double get_energy_crypto_dsa() const noexcept = 0;
    virtual double get_energy_crypto_sym() const noexcept = 0;
    virtual double get_energy_treekem() const noexcept = 0;
};

/**
 * @brief Concrete UAV class orchestrating security modules for autonomous flight networks.
 */
class Uav final : public IUav {
public:
    Uav(std::shared_ptr<IEventBus> event_bus,
        std::shared_ptr<IConfigurationManager> config_mgr,
        std::shared_ptr<ICryptoManager> crypto_mgr,
        std::shared_ptr<INetworkManager> network_mgr,
        std::shared_ptr<ISessionManager> session_mgr,
        std::shared_ptr<IAcpeEngine> acpe_engine);
    ~Uav() override = default;

    VoidResult initialize(const std::string& config_str) override;
    VoidResult start_handshake(Timestamp now_ms) override;
    VoidResult receive_packet(ByteSpan packet, Timestamp now_ms) override;
    VoidResult send_telemetry(ByteSpan payload, Timestamp now_ms = 0) override;
    VoidResult send_video_frame(ByteSpan jpeg_bytes, uint16_t width, uint16_t height, uint32_t frame_seq, Timestamp now_ms) override;
    void set_battery_level(double percent, Timestamp now_ms) override;
    double get_battery_level() const noexcept override { return battery_level_; }
    void update_battery(Timestamp now_ms, double speed_m_s, double climb_rate) override;
    double get_remaining_energy_joules() const noexcept override { return battery_.remaining_energy_joules; }
    std::string get_mission_name() const noexcept override;

    const NodeId& get_node_id() const noexcept override { return node_id_; }
    const std::shared_ptr<ISessionManager>& get_session_manager() const noexcept override { return session_mgr_; }
    void set_certificate(Bytes cert) { cert_ = std::move(cert); }

    // ── Metrics & Lifecycle Getters ──────────────────────────────────────────
    uint32_t get_packets_sent() const noexcept override { return packets_sent_; }
    uint32_t get_packets_received() const noexcept override { return packets_received_; }
    uint32_t get_handshake_count() const noexcept override { return handshake_count_; }
    protocol::HandshakeState get_handshake_state() const noexcept override {
        return handshake_ ? handshake_->state() : protocol::HandshakeState::Failed;
    }
    uint32_t get_auth_count() const noexcept override { return auth_count_; }
    uint32_t get_treekem_rekeys() const noexcept override { return treekem_rekeys_; }
    double get_session_lifetime_sec(Timestamp now_ms) const noexcept override;
    double get_telemetry_interval_ms() const noexcept override;
    bool is_emergency() const noexcept override { return battery_level_ < 10.0; }
    bool is_shutdown() const noexcept override { return shutdown_initiated_; }
    void set_link_stats(double rssi, double sinr, double packet_loss, double latency_ms) noexcept override;
    void trigger_treekem_rekey() noexcept override { treekem_rekeys_++; }
    void set_threat_level(policy::ThreatLevel level) noexcept override { threat_level_ = level; }
    double get_energy_consumed() const noexcept override { return battery_.total_capacity_joules - battery_.remaining_energy_joules; }
    double get_energy_flight() const noexcept override { return battery_.energy_flight; }
    double get_energy_radio_tx() const noexcept override { return battery_.energy_radio_tx; }
    double get_energy_radio_rx() const noexcept override { return battery_.energy_radio_rx; }
    double get_energy_cpu_idle() const noexcept override { return battery_.energy_cpu_idle; }
    double get_energy_crypto_kem() const noexcept override { return battery_.energy_crypto_kem; }
    double get_energy_crypto_dsa() const noexcept override { return battery_.energy_crypto_dsa; }
    double get_energy_crypto_sym() const noexcept override { return battery_.energy_crypto_sym; }
    double get_energy_treekem() const noexcept override { return battery_.energy_treekem; }
    std::string get_active_session_id_hex() const noexcept override;
    double get_treekem_rekey_interval_sec() const noexcept override { return treekem_rekey_interval_sec_; }
    std::uint32_t get_payload_size() const noexcept override { return payload_size_; }
    void set_mission(const UavMission& mission) noexcept override;
    const UavMission& get_mission() const noexcept override { return mission_; }
    bool is_waiting_for_classical_approval() const noexcept override { return waiting_for_classical_approval_; }
    bool is_classical_approved() const noexcept override { return classical_approved_; }
    void approve_classical_mode(std::uint32_t operator_id) override;
    void handle_classical_mode_decision(const mavlink::CommandLong& cmd);
    policy::FsmState get_fsm_state() const noexcept override { return acpe_engine_->get_fsm_state(); }
    BatteryModel& get_battery_model_non_const() noexcept { return battery_; }
    void handle_reassembled_message(const NodeId& src_id, const Bytes& msg);
    void set_treekem_private_key(crypto::KemPrivateKey priv_key);

    // ── Ephemeral D2D Operations ──────────────────────────────────────────────
    VoidResult request_d2d_session(const NodeId& target_node_id, std::uint32_t lifetime_sec = 300);
    Result<Bytes> send_d2d_payload(const NodeId& target_node_id, ByteSpan payload, Timestamp now_ms);
    VoidResult terminate_d2d_session(const NodeId& target_node_id);
    VoidResult initiate_d2d_handshake(const NodeId& target_node_id) override;

    session::D2DSessionManager& get_d2d_manager() noexcept { return d2d_manager_; }
    const session::D2DSessionManager& get_d2d_manager() const noexcept { return d2d_manager_; }

private:
    Bytes cert_;
    std::shared_ptr<IEventBus> event_bus_;
    std::shared_ptr<IConfigurationManager> config_mgr_;
    std::shared_ptr<ICryptoManager> crypto_mgr_;
    std::shared_ptr<INetworkManager> network_mgr_;
    std::shared_ptr<ISessionManager> session_mgr_;
    std::shared_ptr<IAcpeEngine> acpe_engine_;
    session::D2DSessionManager d2d_manager_;

    NodeId node_id_;
    std::unique_ptr<protocol::IHandshake> handshake_;
    std::unique_ptr<protocol::D2DHandshakeManager> d2d_handshake_mgr_;
    void ensure_d2d_handshake_manager();
    SessionId active_session_id_{};
    NodeId    active_peer_id_{};
    double battery_level_ = 100.0;
    mavlink::MavlinkParser mavlink_parser_;

    UavMission mission_;
    BatteryModel battery_;
    Timestamp last_battery_update_ms_ = 0;

    // ── Realism Tracking Variables ───────────────────────────────────────────
    uint32_t packets_sent_ = 0;
    uint32_t packets_received_ = 0;
    uint32_t handshake_count_ = 0;
    uint32_t auth_count_ = 0;
    uint32_t treekem_rekeys_ = 0;
    Timestamp session_established_time_ms_ = 0;
    bool shutdown_initiated_ = false;

    // Cached link quality inputs from simulation environment
    double link_rssi_ = -70.0;
    double link_sinr_ = 15.0;
    double link_packet_loss_ = 0.0;
    double link_latency_ms_ = 5.0;

    double treekem_rekey_interval_sec_ = 30.0;
    std::uint32_t payload_size_ = 0;
    double telemetry_interval_ms_ = 1000.0;
    policy::ThreatLevel threat_level_ = policy::ThreatLevel::Medium;
    bool waiting_for_classical_approval_ = false;
    bool classical_approved_ = false;
    std::optional<policy::AcpeDecision> last_decision_;

    std::shared_ptr<ITreeKemController> treekem_ctrl_;
    crypto::KemPrivateKey treekem_priv_key_;

};

} // namespace uav_pqc::app
