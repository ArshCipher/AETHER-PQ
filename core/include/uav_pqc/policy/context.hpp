// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file context.hpp
 * @brief PolicyContext — runtime inputs to the ACPE decision engine.
 *
 * The ACPE periodically evaluates the PolicyContext and may trigger a profile
 * transition or mode change.  Context values are collected by the application
 * layer and passed to ACPE::evaluate().
 *
 * All fields use simple scalar types so the struct can be serialised to JSON
 * for audit logging without a dedicated serialiser.
 */

#include "uav_pqc/common/types.hpp"
#include "uav_pqc/protocol/mode.hpp"
#include "uav_pqc/policy/profile.hpp"

#include <cstdint>
#include <optional>

namespace uav_pqc::policy {

/**
 * @brief Link quality classification (coarse).
 */
enum class LinkQuality : std::uint8_t {
    Excellent = 0, ///< SNR > 20 dB; full-rate reliable
    Good      = 1, ///< SNR 10–20 dB; occasional retransmission
    Fair      = 2, ///< SNR 5–10 dB; frequent fragmentation
    Poor      = 3, ///< SNR < 5 dB; significant PQC overhead impact
};

/**
 * @brief UAV hardware class affecting available cryptographic operations.
 */
enum class HardwareClass : std::uint8_t {
    Microcontroller = 0, ///< STM32-class; no hardware AES; limited RAM
    EmbeddedLinux   = 1, ///< RPi-class ARM Cortex-A; hardware AES optional
    GroundStation   = 2, ///< x86_64; full AES-NI; large key store
};

/**
 * @brief Mission-driven threat level.
 *
 * Operators set this explicitly (e.g. "commercial inspection" vs "ISR").
 * Higher threat levels prevent downgrade and enforce Hardened profile.
 */
enum class ThreatLevel : std::uint8_t {
    Low      = 0, ///< Commercial, non-safety-critical
    Medium   = 1, ///< Safety-critical, civilian
    High     = 2, ///< Military / ISR / critical infrastructure
};

/**
 * @brief Complete context snapshot provided to the ACPE for policy evaluation.
 */
struct PolicyContext {
    // ── Node hardware ─────────────────────────────────────────────────────────
    HardwareClass hardware_class = HardwareClass::EmbeddedLinux;
    bool          has_hw_aes     = false;  ///< Hardware AES acceleration available

    // ── Power management ──────────────────────────────────────────────────────
    std::uint8_t  battery_percent = 100;   ///< 0–100; below threshold triggers lightweight

    // ── RF link state ─────────────────────────────────────────────────────────
    LinkQuality   link_quality     = LinkQuality::Good;
    std::uint32_t link_data_rate_bps = 250000; ///< Current link data rate (bits/s)

    // ── Swarm state ───────────────────────────────────────────────────────────
    std::uint16_t swarm_size      = 1;     ///< Number of active swarm members (including self)
    bool          swarm_key_active= false; ///< Whether a TreeKEM group key is in use

    // ── Mobility ──────────────────────────────────────────────────────────────
    float         speed_m_s       = 0.0f;  ///< Current airspeed (m/s)

    // ── Mission ───────────────────────────────────────────────────────────────
    ThreatLevel   threat_level    = ThreatLevel::Medium;
    bool          mission_active  = false;

    // ── Peer capability ───────────────────────────────────────────────────────
    bool          peer_supports_pqc     = true;   ///< Peer can run ML-KEM/ML-DSA
    bool          peer_is_legacy        = false;  ///< Peer is a classical-only node

    // ── ACPE Extended Inputs ──────────────────────────────────────────────────
    double        mission_criticality   = 5.0;    ///< 0.0 (low) to 10.0 (critical)
    double        network_congestion    = 0.0;    ///< 0.0 (none) to 1.0 (saturated)
    double        swarm_density         = 0.0;    ///< Swarm density metric (e.g. nodes per unit area)
    double        cpu_utilization       = 0.0;    ///< 0.0 (idle) to 100.0 (saturated)

    // ── Realistic Link Performance & Lifecycle Inputs ────────────────────────
    double        rssi                  = -70.0;  ///< dBm
    double        sinr                  = 15.0;   ///< dB
    double        packet_loss           = 0.0;    ///< 0.0 to 1.0 (or percent)
    double        latency_ms            = 5.0;
    double        session_lifetime_sec  = 0.0;
    double        treekem_update_freq   = 0.0;    ///< updates per minute
    double        memory_utilization    = 20.0;   ///< 0.0 to 100.0
    std::uint32_t neighbour_count       = 0;
    double        cert_lifetime_sec     = 3600.0; ///< certificate lifetime in seconds
    double        security_downgrade_threshold = -95.0;

    // Mission-aware policy contexts
    protocol::OperatingMode default_operating_mode = protocol::OperatingMode::Hybrid;
    CryptographicProfile default_crypto_profile = CryptographicProfile::Standard;
    double telemetry_interval_sec = 1.0;
    std::uint32_t payload_size = 800;
    std::string preferred_cipher_suite = "";
    double treekem_rekey_interval_sec = 30.0;
    std::uint32_t session_lifetime_sec_limit = 1200;
    double battery_consumption_multiplier = 1.0;
    double communication_priority = 5.0;
    double neighbor_sync_rate = 1.0;
    bool video_streaming_enabled = true;

    // ── Battery thresholds that trigger profile downgrade ─────────────────────
    static constexpr std::uint8_t kBatteryThresholdLightweight = 20; ///< < 20% → Lightweight
    static constexpr std::uint8_t kBatteryThresholdStandard    = 50; ///< < 50% → Standard cap
};

} // namespace uav_pqc::policy
