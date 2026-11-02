// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file acpe.cpp
 * @brief Rule-based and Configurable ACPE implementation.
 */

#include "uav_pqc/policy/acpe.hpp"
#include "uav_pqc/common/logging.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cmath>
#include <algorithm>

namespace uav_pqc::policy {

namespace {

double get_field_value(const PolicyContext& ctx, const std::string& field) {
    if (field == "battery_percent") return ctx.battery_percent;
    if (field == "mission_criticality") return ctx.mission_criticality;
    if (field == "network_congestion") return ctx.network_congestion;
    if (field == "swarm_density") return ctx.swarm_density;
    if (field == "mobility") return ctx.speed_m_s;
    if (field == "speed_m_s") return ctx.speed_m_s;
    if (field == "cpu_utilization") return ctx.cpu_utilization;
    if (field == "swarm_size") return ctx.swarm_size;
    return 0.0;
}

bool check_condition(double field_val, const std::string& op, double target_val) {
    if (op == "lt") return field_val < target_val;
    if (op == "lte") return field_val <= target_val;
    if (op == "gt") return field_val > target_val;
    if (op == "gte") return field_val >= target_val;
    if (op == "eq") return std::abs(field_val - target_val) < 1e-9;
    return false;
}

CryptographicProfile parse_profile(const std::string& p) {
    if (p == "Lightweight") return CryptographicProfile::Lightweight;
    if (p == "Hardened") return CryptographicProfile::Hardened;
    return CryptographicProfile::Standard;
}

protocol::OperatingMode parse_mode(const std::string& m) {
    if (m == "Classical") return protocol::OperatingMode::Classical;
    if (m == "Transition") return protocol::OperatingMode::Transition;
    if (m == "PqcOnly") return protocol::OperatingMode::PqcOnly;
    return protocol::OperatingMode::Hybrid;
}

} // namespace

// ── Constructor ───────────────────────────────────────────────────────────────

RuleBasedAcpe::RuleBasedAcpe(ProfileParameters lw, ProfileParameters std_,
                             ProfileParameters hrd)
    : lightweight_(std::move(lw)),
      standard_(std::move(std_)),
      hardened_(std::move(hrd)) {}

// ── select_profile ────────────────────────────────────────────────────────────

CryptographicProfile RuleBasedAcpe::select_profile(const PolicyContext& ctx) const noexcept {
    // Rule 1: Microcontroller → always Lightweight
    if (ctx.hardware_class == HardwareClass::Microcontroller) {
        return CryptographicProfile::Lightweight;
    }

    // Rule 2: Critical battery → Lightweight
    if (ctx.battery_percent < PolicyContext::kBatteryThresholdLightweight) {
        return CryptographicProfile::Lightweight;
    }

    // Rule 3: High threat level → Hardened
    if (ctx.threat_level == ThreatLevel::High) {
        return CryptographicProfile::Hardened;
    }

    // Rule 4: Moderate battery and poor link → Standard to reduce overhead
    if (ctx.battery_percent < PolicyContext::kBatteryThresholdStandard ||
        ctx.link_quality == LinkQuality::Poor) {
        return CryptographicProfile::Standard;
    }

    // Default
    return CryptographicProfile::Standard;
}

// ── select_mode ───────────────────────────────────────────────────────────────

protocol::OperatingMode RuleBasedAcpe::select_mode(
    const PolicyContext& ctx, CryptographicProfile profile) const noexcept {

    // Legacy peer → restrict to modes that include classical algorithms
    if (ctx.peer_is_legacy || !ctx.peer_supports_pqc) {
        return protocol::OperatingMode::Classical;
    }

    switch (profile) {
        case CryptographicProfile::Lightweight:
            return protocol::OperatingMode::Transition;

        case CryptographicProfile::Standard:
            return protocol::OperatingMode::Hybrid;

        case CryptographicProfile::Hardened:
            return protocol::OperatingMode::PqcOnly;
    }
    return protocol::OperatingMode::Hybrid;
}

// ── build_suite ───────────────────────────────────────────────────────────────

protocol::CipherSuite RuleBasedAcpe::build_suite(
    protocol::OperatingMode    mode,
    const ProfileParameters&   params,
    const PolicyContext&       ctx) const {

    protocol::AeadAlgorithm aead = params.preferred_aead;
    if (!ctx.has_hw_aes && params.profile != CryptographicProfile::Hardened) {
        aead = params.fallback_aead;
    }

    switch (mode) {
        case protocol::OperatingMode::Classical:
            return protocol::CipherSuite::make_classical(aead);
        case protocol::OperatingMode::Transition:
            return protocol::CipherSuite::make_transition(params.kem_level, aead);
        case protocol::OperatingMode::Hybrid:
            return protocol::CipherSuite::make_hybrid(aead);
        case protocol::OperatingMode::PqcOnly:
            return protocol::CipherSuite::make_pqc_only(params.kem_level, params.dsa_level, aead);
    }
    return protocol::CipherSuite::make_hybrid(aead);
}

// ── handle_event ─────────────────────────────────────────────────────────────

void RuleBasedAcpe::handle_event(AcpeEvent ev, const PolicyContext& ctx) {
    // Hierarchical conditions definitions
    auto is_shutdown = [](const PolicyContext& c) { return c.battery_percent == 0.0; };
    auto is_critical_battery = [](const PolicyContext& c) { return c.battery_percent < 10.0; };
    auto is_low_battery = [](const PolicyContext& c) { return c.battery_percent < 20.0; };
    auto is_battery_40 = [](const PolicyContext& c) { return c.battery_percent < 40.0; };
    auto is_battery_70 = [](const PolicyContext& c) { return c.battery_percent < 70.0; };
    auto is_high_threat = [](const PolicyContext& c) { return c.threat_level == ThreatLevel::High; };
    auto is_weak_channel = [](const PolicyContext& c) { return c.packet_loss > 0.15 || c.rssi < -85.0 || c.sinr < 3.0; };
    auto is_congested = [](const PolicyContext& c) { return c.network_congestion > 0.7 || c.cpu_utilization > 80.0; };

    // Transition table defining deterministic FSM rules
    struct Transition {
        PolicyState from_policy;
        AcpeEvent event;
        std::function<bool(const PolicyContext&)> guard;
        PolicyState to_policy;
        OperatingState to_operating;
        OperationalState to_operational;
        CryptographicProfile to_profile;
        std::string reason;
    };

    static const std::vector<Transition> transition_table = {
        // ── Operator Overrides (Manual Override Mode) ────────────────────────
        { PolicyState::AutomaticPolicy, AcpeEvent::OperatorOverride, nullptr,
          PolicyState::ManualPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Standard,
          "Manual Operator Override Initiated" },
        { PolicyState::ManualPolicy, AcpeEvent::OperatorOverride, nullptr,
          PolicyState::ManualPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Standard,
          "Manual Operator Override Updated" },
        { PolicyState::ManualPolicy, AcpeEvent::OperatorResumeAutomatic, nullptr,
          PolicyState::AutomaticPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Standard,
          "Operator Resumed Automatic Mode" },

        // ── Battery Shutdown (Valid in both Automatic & Manual Policy) ───────
        { PolicyState::AutomaticPolicy, AcpeEvent::BatteryChanged, is_shutdown,
          PolicyState::AutomaticPolicy, OperatingState::Transition, OperationalState::Shutdown, CryptographicProfile::Lightweight,
          "Battery exhausted (0%)" },
        { PolicyState::ManualPolicy, AcpeEvent::BatteryChanged, is_shutdown,
          PolicyState::ManualPolicy, OperatingState::Transition, OperationalState::Shutdown, CryptographicProfile::Lightweight,
          "Battery exhausted (0%)" },

        // ── Battery Tiers (Automatic Policy only) ────────────────────────────
        { PolicyState::AutomaticPolicy, AcpeEvent::BatteryChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && is_critical_battery(c); },
          PolicyState::AutomaticPolicy, OperatingState::Transition, OperationalState::EmergencyCommunication, CryptographicProfile::Lightweight,
          "Critical battery (<10%), entering emergency mode" },

        { PolicyState::AutomaticPolicy, AcpeEvent::BatteryChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_critical_battery(c) && is_low_battery(c); },
          PolicyState::AutomaticPolicy, OperatingState::Transition, OperationalState::Normal, CryptographicProfile::Lightweight,
          "Low battery (<20%), emergency communication profile" },

        { PolicyState::AutomaticPolicy, AcpeEvent::BatteryChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_low_battery(c) && is_battery_40(c); },
          PolicyState::AutomaticPolicy, OperatingState::Transition, OperationalState::Normal, CryptographicProfile::Lightweight,
          "Battery below 40%, transitioning to Transition mode" },

        { PolicyState::AutomaticPolicy, AcpeEvent::BatteryChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_40(c) && is_battery_70(c); },
          PolicyState::AutomaticPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Lightweight,
          "Battery below 70%, switching to Lightweight profile" },

        { PolicyState::AutomaticPolicy, AcpeEvent::BatteryChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && !is_high_threat(c) && !is_weak_channel(c) && !is_congested(c); },
          PolicyState::AutomaticPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Standard,
          "Normal battery level restored (>=70%)" },

        // ── High Threat ──────────────────────────────────────────────────────
        { PolicyState::AutomaticPolicy, AcpeEvent::ThreatChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && is_high_threat(c); },
          PolicyState::AutomaticPolicy, OperatingState::PQCOnly, OperationalState::Normal, CryptographicProfile::Hardened,
          "High threat level detected, enforcing Hardened PQCOnly profile" },

        { PolicyState::AutomaticPolicy, AcpeEvent::ThreatChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && !is_high_threat(c) && !is_weak_channel(c) && !is_congested(c); },
          PolicyState::AutomaticPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Standard,
          "Normal threat level restored" },

        // ── Extreme Channel Degradation (Classical Recommendation) ────────────
        { PolicyState::AutomaticPolicy, AcpeEvent::RSSIChanged,
          [](const PolicyContext& c) { return c.battery_percent != 0.0 && (c.rssi < -85.0 || c.packet_loss > 50.0 || c.sinr < 3.0); },
          PolicyState::AutomaticPolicy, OperatingState::Classical, OperationalState::Normal, CryptographicProfile::Lightweight,
          "Severe link degradation: Classical mode recommended to improve availability" },
        { PolicyState::AutomaticPolicy, AcpeEvent::PacketLossChanged,
          [](const PolicyContext& c) { return c.battery_percent != 0.0 && (c.rssi < -85.0 || c.packet_loss > 50.0 || c.sinr < 3.0); },
          PolicyState::AutomaticPolicy, OperatingState::Classical, OperationalState::Normal, CryptographicProfile::Lightweight,
          "Severe packet loss: Classical mode recommended to improve availability" },
        { PolicyState::AutomaticPolicy, AcpeEvent::SINRChanged,
          [](const PolicyContext& c) { return c.battery_percent != 0.0 && (c.rssi < -85.0 || c.packet_loss > 50.0 || c.sinr < 3.0); },
          PolicyState::AutomaticPolicy, OperatingState::Classical, OperationalState::Normal, CryptographicProfile::Lightweight,
          "Severe SINR drop: Classical mode recommended to improve availability" },

        // ── Weak Channel Quality (RSSI / Packet Loss) ────────────────────────
        { PolicyState::AutomaticPolicy, AcpeEvent::RSSIChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && !is_high_threat(c) && is_weak_channel(c); },
          PolicyState::AutomaticPolicy, OperatingState::Transition, OperationalState::Normal, CryptographicProfile::Lightweight,
          "Weak channel quality (RSSI/loss), downgrading to reduce fragmentation" },

        { PolicyState::AutomaticPolicy, AcpeEvent::PacketLossChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && !is_high_threat(c) && is_weak_channel(c); },
          PolicyState::AutomaticPolicy, OperatingState::Transition, OperationalState::Normal, CryptographicProfile::Lightweight,
          "Weak channel quality (RSSI/loss), downgrading to reduce fragmentation" },

        { PolicyState::AutomaticPolicy, AcpeEvent::RSSIChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && !is_high_threat(c) && !is_weak_channel(c) && !is_congested(c); },
          PolicyState::AutomaticPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Standard,
          "Channel quality restored to normal" },

        { PolicyState::AutomaticPolicy, AcpeEvent::PacketLossChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && !is_high_threat(c) && !is_weak_channel(c) && !is_congested(c); },
          PolicyState::AutomaticPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Standard,
          "Channel quality restored to normal" },

        // ── Congestion / CPU load ────────────────────────────────────────────
        { PolicyState::AutomaticPolicy, AcpeEvent::CongestionChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && !is_high_threat(c) && !is_weak_channel(c) && is_congested(c); },
          PolicyState::AutomaticPolicy, OperatingState::Transition, OperationalState::Normal, CryptographicProfile::Lightweight,
          "High network congestion / CPU load, reducing cryptographic overhead" },

        { PolicyState::AutomaticPolicy, AcpeEvent::CongestionChanged,
          [&](const PolicyContext& c) { return !is_shutdown(c) && !is_battery_70(c) && !is_high_threat(c) && !is_weak_channel(c) && !is_congested(c); },
          PolicyState::AutomaticPolicy, OperatingState::Hybrid, OperationalState::Normal, CryptographicProfile::Standard,
          "Congestion / CPU load restored to normal" },

        // ── Emergency Mode ───────────────────────────────────────────────────
        { PolicyState::AutomaticPolicy, AcpeEvent::EmergencyDetected, nullptr,
          PolicyState::AutomaticPolicy, OperatingState::Transition, OperationalState::EmergencyCommunication, CryptographicProfile::Lightweight,
          "Emergency detected, entering emergency mode" }
    };

    // Evaluate matching transition rules
    for (const auto& trans : transition_table) {
        if (trans.from_policy == current_state_.policy && trans.event == ev) {
            if (!trans.guard || trans.guard(ctx)) {
                // Apply FSM transitions
                current_state_.policy = trans.to_policy;
                current_state_.operating = trans.to_operating;
                current_state_.operational = trans.to_operational;
                current_state_.profile = trans.to_profile;
                current_state_.reason = trans.reason;

                // Adjust values under manual OperatorOverride
                if (ev == AcpeEvent::OperatorOverride) {
                    // Map override_mode_ back to OperatingState
                    switch (override_mode_) {
                        case protocol::OperatingMode::Classical:  current_state_.operating = OperatingState::Classical; break;
                        case protocol::OperatingMode::Transition: current_state_.operating = OperatingState::Transition; break;
                        case protocol::OperatingMode::Hybrid:     current_state_.operating = OperatingState::Hybrid; break;
                        case protocol::OperatingMode::PqcOnly:    current_state_.operating = OperatingState::PQCOnly; break;
                    }
                    current_state_.profile = override_profile_;
                }

                // Microcontrollers are forced to Lightweight profile
                if (ctx.hardware_class == HardwareClass::Microcontroller) {
                    current_state_.profile = CryptographicProfile::Lightweight;
                }
                break;
            }
        }
    }
}

// ── Operator Commands ────────────────────────────────────────────────────────

void RuleBasedAcpe::trigger_operator_override(protocol::OperatingMode mode, CryptographicProfile profile) {
    SetOperatingMode(mode);
    SetCryptoProfile(profile);
}

void RuleBasedAcpe::trigger_operator_resume() {
    PolicyContext dummy;
    if (last_ctx_) dummy = *last_ctx_;
    handle_event(AcpeEvent::OperatorResumeAutomatic, dummy);
    last_ctx_ = std::nullopt;
    evaluate(dummy);
}

void RuleBasedAcpe::EnableAutomatic() {
    trigger_operator_resume();
}

void RuleBasedAcpe::DisableAutomatic() {
    current_state_.policy = PolicyState::ManualPolicy;
    UAV_PQC_LOG_INFO("policy.acpe", "Manual control locked: Automatic policy evaluation disabled.");
}

void RuleBasedAcpe::SetOperatingMode(protocol::OperatingMode mode) {
    override_mode_ = mode;
    current_state_.policy = PolicyState::ManualPolicy;
    switch (mode) {
        case protocol::OperatingMode::Classical:  current_state_.operating = OperatingState::Classical; break;
        case protocol::OperatingMode::Transition: current_state_.operating = OperatingState::Transition; break;
        case protocol::OperatingMode::Hybrid:     current_state_.operating = OperatingState::Hybrid; break;
        case protocol::OperatingMode::PqcOnly:    current_state_.operating = OperatingState::PQCOnly; break;
    }
    current_state_.reason = "Operator manually selected OperatingMode";
    UAV_PQC_LOG_INFO("policy.acpe", "Operator manual override OperatingMode: {}", protocol::to_string(mode));
    if (last_ctx_) {
        if (last_ctx_->hardware_class == HardwareClass::Microcontroller) {
            current_state_.profile = CryptographicProfile::Lightweight;
        }
        evaluate(*last_ctx_);
    }
}

void RuleBasedAcpe::SetCryptoProfile(CryptographicProfile profile) {
    override_profile_ = profile;
    current_state_.policy = PolicyState::ManualPolicy;
    current_state_.profile = profile;
    current_state_.reason = "Operator manually selected CryptoProfile";
    UAV_PQC_LOG_INFO("policy.acpe", "Operator manual override CryptoProfile: {}", to_string(profile));
    if (last_ctx_) {
        if (last_ctx_->hardware_class == HardwareClass::Microcontroller) {
            current_state_.profile = CryptographicProfile::Lightweight;
        }
        evaluate(*last_ctx_);
    }
}

void RuleBasedAcpe::EmergencyOverride() {
    current_state_.policy = PolicyState::ManualPolicy;
    current_state_.operating = OperatingState::Transition;
    current_state_.operational = OperationalState::EmergencyCommunication;
    current_state_.profile = CryptographicProfile::Lightweight;
    current_state_.reason = "Emergency override requested by operator";
    UAV_PQC_LOG_WARN("policy.acpe", "EMERGENCY OVERRIDE: Forcing state to EmergencyCommunication");
    if (last_ctx_) {
        evaluate(*last_ctx_);
    }
}

void RuleBasedAcpe::ResumeAutomatic() {
    EnableAutomatic();
}

// ── evaluate ─────────────────────────────────────────────────────────────────

Result<AcpeDecision> RuleBasedAcpe::evaluate(const PolicyContext& ctx) {
    std::uint32_t rekey_interval = 0;
    std::uint32_t session_lifetime = 0;

    if (has_loaded_rules_) {
        // Fall back to rule engine if json rules are loaded
        CryptographicProfile profile = CryptographicProfile::Standard;
        protocol::OperatingMode mode = protocol::OperatingMode::Hybrid;
        std::string rationale;

        bool matched = false;
        for (const auto& rule : rules_) {
            bool rule_matched = false;
            if (rule.conditions.empty()) {
                rule_matched = true;
            } else {
                bool all_conds = true;
                bool any_conds = false;
                for (const auto& cond : rule.conditions) {
                    double field_val = get_field_value(ctx, cond.field);
                    bool cond_res = check_condition(field_val, cond.op, cond.value);
                    if (cond_res) {
                        any_conds = true;
                    } else {
                        all_conds = false;
                    }
                }
                if (rule.any_or_all == "any") {
                    rule_matched = any_conds;
                } else {
                    rule_matched = all_conds;
                }
            }

            if (rule_matched) {
                profile = parse_profile(rule.actions.profile);
                mode = parse_mode(rule.actions.mode);
                rekey_interval = rule.actions.rekey_interval_seconds;
                session_lifetime = rule.actions.session_lifetime_seconds;
                rationale = "Matched custom rule: profile=" + rule.actions.profile + " mode=" + rule.actions.mode;
                matched = true;
                break;
            }
        }

        if (!matched) {
            profile = parse_profile(default_actions_.profile);
            mode = parse_mode(default_actions_.mode);
            rekey_interval = default_actions_.rekey_interval_seconds;
            session_lifetime = default_actions_.session_lifetime_seconds;
            rationale = "Fallback to default config: profile=" + default_actions_.profile + " mode=" + default_actions_.mode;
        }

        const ProfileParameters& params = [&]() -> const ProfileParameters& {
            switch (profile) {
                case CryptographicProfile::Lightweight: return lightweight_;
                case CryptographicProfile::Standard:    return standard_;
                case CryptographicProfile::Hardened:    return hardened_;
            }
            return standard_;
        }();

        protocol::CipherSuite suite = build_suite(mode, params, ctx);
        suite.max_session_seconds = session_lifetime;

        const bool rekey_now = last_decision_.has_value() && (last_decision_->suite != suite);

        AcpeDecision decision;
        decision.mode = mode;
        decision.profile = profile;
        decision.suite = suite;
        decision.rekey_now = rekey_now;
        decision.rationale = rationale;
        decision.rekey_interval_seconds = rekey_interval;
        decision.session_lifetime_seconds = session_lifetime;

        if (change_handler_ && rekey_now) {
            change_handler_(decision);
        }
        last_decision_ = decision;
        return ok<AcpeDecision>(decision);

    } else {
        // Evaluate FSM events based on context updates
        if (!last_ctx_) {
            last_ctx_ = ctx;
            handle_event(AcpeEvent::BatteryChanged, ctx);
            handle_event(AcpeEvent::ThreatChanged, ctx);
            handle_event(AcpeEvent::RSSIChanged, ctx);
            handle_event(AcpeEvent::CongestionChanged, ctx);
        } else {
            if (ctx.battery_percent != last_ctx_->battery_percent) {
                handle_event(AcpeEvent::BatteryChanged, ctx);
            }
            if (ctx.threat_level != last_ctx_->threat_level) {
                handle_event(AcpeEvent::ThreatChanged, ctx);
            }
            if (ctx.rssi != last_ctx_->rssi || ctx.packet_loss != last_ctx_->packet_loss) {
                handle_event(AcpeEvent::RSSIChanged, ctx);
            }
            if (ctx.network_congestion != last_ctx_->network_congestion || ctx.cpu_utilization != last_ctx_->cpu_utilization) {
                handle_event(AcpeEvent::CongestionChanged, ctx);
            }
            last_ctx_ = ctx;
        }

        // Print comprehensive decision variable trace logs
        std::cout << "[ACPE TRACE] Battery=" << static_cast<int>(ctx.battery_percent)
                  << "% Criticality=" << ctx.mission_criticality
                  << " Threat=" << static_cast<int>(ctx.threat_level)
                  << " RSSI=" << ctx.rssi << "dBm"
                  << " SINR=" << ctx.sinr << "dB"
                  << " Loss=" << ctx.packet_loss
                  << " Latency=" << ctx.latency_ms << "ms"
                  << " Congestion=" << ctx.network_congestion
                  << " CPU=" << ctx.cpu_utilization << "%"
                  << " Memory=" << ctx.memory_utilization << "%"
                  << " Neighbors=" << ctx.neighbour_count
                  << " TreeKEMFreq=" << ctx.treekem_update_freq
                  << " SessionLife=" << ctx.session_lifetime_sec << "s"
                  << " CertLife=" << ctx.cert_lifetime_sec << "s" << std::endl;

        protocol::OperatingMode mode = ctx.default_operating_mode;
        CryptographicProfile profile = ctx.default_crypto_profile;
        std::uint32_t telemetry_interval = static_cast<std::uint32_t>(ctx.telemetry_interval_sec * 1000.0);
        std::uint32_t payload_sz = ctx.payload_size;
        double tk_interval = ctx.treekem_rekey_interval_sec;
        std::string reason = "Mission Default Policy";

        protocol::OperatingMode rec_mode = mode;
        std::string rec_reason = "";
        std::uint64_t rec_timestamp = 0;
        std::uint32_t rec_id = 0;

        // Deterministic Priority Chain

        // Priority 1: Emergency Shutdown
        if (ctx.battery_percent == 0) {
            mode = protocol::OperatingMode::Transition;
            profile = CryptographicProfile::Lightweight;
            telemetry_interval = 999999;
            payload_sz = 0;
            tk_interval = 0.0;
            reason = "Emergency Shutdown: battery exhausted (0%)";
        }
        // Priority 2: Manual Override
        else if (current_state_.policy == PolicyState::ManualPolicy) {
            switch (current_state_.operating) {
                case OperatingState::Classical:  mode = protocol::OperatingMode::Classical; break;
                case OperatingState::Transition: mode = protocol::OperatingMode::Transition; break;
                case OperatingState::Hybrid:     mode = protocol::OperatingMode::Hybrid; break;
                case OperatingState::PQCOnly:    mode = protocol::OperatingMode::PqcOnly; break;
            }
            profile = current_state_.profile;
            reason = current_state_.reason;

            if (current_state_.operational == OperationalState::EmergencyCommunication) {
                telemetry_interval = 10000;
                payload_sz = 0;
            }
        }
        // Priority 3: Mission Criticality
        else if (ctx.mission_criticality >= 8.0) {
            if (ctx.battery_percent < 10) {
                mode = protocol::OperatingMode::Transition;
                profile = CryptographicProfile::Lightweight;
                telemetry_interval = 10000;
                payload_sz = 0;
                reason = "Mission critical but battery critical (<10%): Emergency Mode";
            } else {
                if (ctx.threat_level == ThreatLevel::High) {
                    mode = protocol::OperatingMode::PqcOnly;
                    profile = CryptographicProfile::Hardened;
                    reason = "Mission critical (>=8.0) + High threat: Hardened PQC-Only";
                } else if (ctx.rssi < -85.0 || ctx.packet_loss > 0.50 || ctx.sinr < 3.0) {
                    mode = protocol::OperatingMode::Classical;
                    profile = CryptographicProfile::Lightweight;
                    reason = "Mission critical but extreme degradation: Classical recommended";
                } else {
                    mode = protocol::OperatingMode::Hybrid;
                    profile = CryptographicProfile::Hardened;
                    reason = "Mission critical: Enforcing Hardened Hybrid mode";
                }
                telemetry_interval = 500;
            }
        }
        // Priority 4: Threat
        else if (ctx.threat_level == ThreatLevel::High) {
            if (ctx.battery_percent < 20) {
                mode = protocol::OperatingMode::Transition;
                profile = CryptographicProfile::Lightweight;
                telemetry_interval = 5000;
                payload_sz = 0;
                reason = "High threat but battery low (<20%): Lightweight Transition";
            } else if (ctx.rssi < -85.0 || ctx.packet_loss > 0.50 || ctx.sinr < 3.0) {
                mode = protocol::OperatingMode::Classical;
                profile = CryptographicProfile::Lightweight;
                reason = "High threat but extreme degradation: Classical recommended";
            } else {
                mode = protocol::OperatingMode::PqcOnly;
                profile = CryptographicProfile::Hardened;
                reason = "High threat level detected: Enforcing Hardened PQC-Only";
            }
        }
        // Priority 5: Battery Tiers
        else if (ctx.battery_percent < 10) {
            mode = protocol::OperatingMode::Transition;
            profile = CryptographicProfile::Lightweight;
            telemetry_interval = 10000;
            payload_sz = 0;
            reason = "Critical battery (<10%): Emergency Communication Mode";
        } else if (ctx.battery_percent < 20) {
            mode = protocol::OperatingMode::Transition;
            profile = CryptographicProfile::Lightweight;
            telemetry_interval = 5000;
            payload_sz = 0;
            reason = "Low battery (<20%): Transition mode + Lightweight profile";
        } else if (ctx.battery_percent < 40) {
            mode = protocol::OperatingMode::Transition;
            profile = CryptographicProfile::Lightweight;
            telemetry_interval = 2000;
            payload_sz = 0;
            reason = "Battery 20%-40%: Transition mode + Lightweight profile";
        } else if (ctx.battery_percent < 70) {
            mode = protocol::OperatingMode::Hybrid;
            profile = CryptographicProfile::Lightweight;
            reason = "Battery 40%-70%: Hybrid mode + Lightweight profile";
        }
        // Priority 6: Channel Quality
        else if (ctx.rssi < -80.0 || ctx.packet_loss > 0.15 || ctx.sinr < 5.0) {
            // Step 1: Remain in current mode if communication quality remains acceptable
            if (ctx.rssi >= -82.0 && ctx.packet_loss <= 0.20 && ctx.sinr >= 4.0) {
                mode = protocol::OperatingMode::Hybrid;
                profile = CryptographicProfile::Standard;
                reason = "[CQ Step 1] Slightly degraded link: remaining in Hybrid/Standard mode";
            }
            // Step 2: Switch to Lightweight Profile
            else if (ctx.rssi >= -84.0 && ctx.packet_loss <= 0.30 && ctx.sinr >= 3.5) {
                mode = protocol::OperatingMode::Hybrid;
                profile = CryptographicProfile::Lightweight;
                reason = "[CQ Step 2] Degraded link: switching to Lightweight Profile";
            }
            // Step 3: Reduce telemetry frequency
            else if (ctx.rssi >= -86.0 && ctx.packet_loss <= 0.40 && ctx.sinr >= 3.0) {
                mode = protocol::OperatingMode::Hybrid;
                profile = CryptographicProfile::Lightweight;
                telemetry_interval = 5000; // increase telemetry interval
                reason = "[CQ Step 3] Weak link: reducing telemetry frequency to 5s";
            }
            // Step 4: Reduce payload size
            else if (ctx.rssi >= -88.0 && ctx.packet_loss <= 0.50 && ctx.sinr >= 2.5) {
                mode = protocol::OperatingMode::Hybrid;
                profile = CryptographicProfile::Lightweight;
                telemetry_interval = 5000;
                payload_sz = 0; // suspend non-essential traffic
                reason = "[CQ Step 4] Very weak link: reducing payload size to 0 bytes";
            }
            // Step 5: Increase TreeKEM rekey interval where security policy permits
            else if (ctx.rssi >= -90.0 && ctx.packet_loss <= 0.60 && ctx.sinr >= 2.0) {
                mode = protocol::OperatingMode::Hybrid;
                profile = CryptographicProfile::Lightweight;
                telemetry_interval = 5000;
                payload_sz = 0;
                tk_interval = 60.0; // slow down rekey interval
                reason = "[CQ Step 5] Extremely weak link: increasing TreeKEM rekey interval to 60s";
            }
            // Step 6: Transition Mode if appropriate
            else if (ctx.rssi >= ctx.security_downgrade_threshold) {
                mode = protocol::OperatingMode::Transition;
                profile = CryptographicProfile::Lightweight;
                telemetry_interval = 5000;
                payload_sz = 0;
                tk_interval = 60.0;
                reason = "[CQ Step 6] Critical link: switching to Transition Mode";
            }
            // Step 7: Re-evaluate. Only if quality is below security_downgrade_threshold:
            else {
                mode = protocol::OperatingMode::Transition; // UAV continues operating in Transition Mode
                profile = CryptographicProfile::Lightweight;
                telemetry_interval = 5000;
                payload_sz = 0;
                tk_interval = 60.0;
                reason = "[CQ Step 7] Absolute last resort: Classical Mode recommended";

                rec_mode = protocol::OperatingMode::Classical;
                rec_reason = "Severe link degradation: Classical mode recommended to improve availability";
                static std::uint32_t rec_id_counter = 1000;
                rec_timestamp = 1783000000;
                rec_id = ++rec_id_counter;
            }
        }
        // Priority 7: Resources
        else if (ctx.cpu_utilization > 80.0 || ctx.network_congestion > 0.7 || ctx.memory_utilization > 80.0) {
            mode = protocol::OperatingMode::Transition;
            profile = CryptographicProfile::Lightweight;
            reason = "High resource utilization (CPU/Memory/Congestion): Reducing complexity";
        }
        // Priority 8: Default Policy
        else {
            mode = protocol::OperatingMode::Hybrid;
            profile = CryptographicProfile::Standard;
            reason = "Default starting profile: Normal operation";
        }

        // Hardware client constraint
        if (ctx.hardware_class == HardwareClass::Microcontroller) {
            profile = CryptographicProfile::Lightweight;
            if (mode == protocol::OperatingMode::Hybrid || mode == protocol::OperatingMode::PqcOnly) {
                mode = protocol::OperatingMode::Transition;
            }
            reason = "Microcontroller client constraint (forces Transition/Lightweight)";
        }

        // Legacy peer restriction enforces Classical mode
        if (ctx.peer_is_legacy || !ctx.peer_supports_pqc) {
            mode = protocol::OperatingMode::Classical;
        }

        const ProfileParameters& params = [&]() -> const ProfileParameters& {
            switch (profile) {
                case CryptographicProfile::Lightweight: return lightweight_;
                case CryptographicProfile::Standard:    return standard_;
                case CryptographicProfile::Hardened:    return hardened_;
            }
            return standard_;
        }();

        rekey_interval = params.rekey_interval_seconds;
        session_lifetime = (ctx.session_lifetime_sec_limit > 0) ? ctx.session_lifetime_sec_limit : (params.rekey_interval_seconds * 2);

        protocol::CipherSuite suite = build_suite(mode, params, ctx);
        suite.max_session_seconds = session_lifetime;

        const bool rekey_now = last_decision_.has_value() && (last_decision_->suite != suite);

        AcpeDecision decision;
        decision.mode = mode;
        decision.profile = profile;
        decision.suite = suite;
        decision.rekey_now = rekey_now;
        decision.rationale = reason;
        decision.rekey_interval_seconds = rekey_interval;
        decision.session_lifetime_seconds = session_lifetime;
        decision.telemetry_interval_ms = telemetry_interval;
        decision.payload_size = payload_sz;
        decision.treekem_rekey_interval_sec = tk_interval;
        decision.recommended_mode = rec_mode;
        decision.recommendation_reason = rec_reason;
        decision.recommendation_timestamp = rec_timestamp;
        decision.recommendation_id = rec_id;

        if (rec_mode == protocol::OperatingMode::Classical && current_state_.policy == PolicyState::AutomaticPolicy) {
            decision.classical_recommended = true;
        }

        std::cout << "[ACPE DECISION] Mode=" << protocol::to_string(mode)
                  << " Profile=" << to_string(profile)
                  << " TelemetryPolicy=" << telemetry_interval << "ms"
                  << " PayloadPolicy=" << payload_sz << "B"
                  << " TreeKEMInterval=" << tk_interval << "s"
                  << " SessionLifetime=" << session_lifetime << "s"
                  << " Rationale=\"" << reason << "\"" << std::endl;

        UAV_PQC_LOG_DEBUG("policy.acpe", "FSM Decision: {} {} rekey_now={} rekey_interval={}s lifetime={}s Rationale: {}",
                         to_string(profile), protocol::to_string(mode), rekey_now, rekey_interval, session_lifetime, decision.rationale);

        if (change_handler_ && rekey_now) {
            UAV_PQC_LOG_INFO("policy.acpe", "FSM Policy changed → {} {} — triggering rekey",
                             to_string(profile), protocol::to_string(mode));
            change_handler_(decision);
        }

        last_decision_ = decision;
        return ok<AcpeDecision>(decision);
    }
}

// ── set_policy_change_handler ─────────────────────────────────────────────────

void RuleBasedAcpe::set_policy_change_handler(AcpePolicyChangeFn fn) {
    change_handler_ = std::move(fn);
}

// ── last_decision ─────────────────────────────────────────────────────────────

Result<AcpeDecision> RuleBasedAcpe::last_decision() const {
    if (!last_decision_.has_value()) {
        return err<AcpeDecision>(ErrorCode::UnsupportedOperation,
            "ACPE::last_decision() called before first evaluate()");
    }
    return ok<AcpeDecision>(*last_decision_);
}

// ── validate_peer_suite ───────────────────────────────────────────────────────

VoidResult RuleBasedAcpe::validate_peer_suite(
    const protocol::CipherSuite& proposed,
    const PolicyContext& ctx) const {

    const CryptographicProfile required = select_profile(ctx);
    if (required == CryptographicProfile::Hardened) {
        if (!proposed.is_quantum_resistant()) {
            return err(ErrorCode::DowngradeRejected,
                "ACPE: Hardened profile requires quantum-resistant key establishment");
        }
        if (proposed.mode != protocol::OperatingMode::PqcOnly &&
            proposed.mode != protocol::OperatingMode::Hybrid) {
            return err(ErrorCode::DowngradeRejected,
                "ACPE: Hardened profile does not accept Classical or Transition mode");
        }
    }

    if (ctx.peer_supports_pqc && proposed.mode == protocol::OperatingMode::Classical
        && required != CryptographicProfile::Lightweight) {
        return err(ErrorCode::DowngradeRejected,
            "ACPE: Downgrade to Classical mode rejected (peer supports PQC)");
    }

    return ok();
}

// ── load_rules_json ──────────────────────────────────────────────────────────

VoidResult RuleBasedAcpe::load_rules_json(ByteSpan json_bytes) {
    try {
        std::string json_str(reinterpret_cast<const char*>(json_bytes.data()), json_bytes.size());
        auto root = nlohmann::json::parse(json_str);

        std::vector<Rule> parsed_rules;
        if (root.contains("rules") && root["rules"].is_array()) {
            for (const auto& r_json : root["rules"]) {
                Rule r;
                if (r_json.contains("any_or_all") && r_json["any_or_all"].is_string()) {
                    r.any_or_all = r_json["any_or_all"].get<std::string>();
                }
                if (r_json.contains("conditions") && r_json["conditions"].is_array()) {
                    for (const auto& c_json : r_json["conditions"]) {
                        RuleCondition cond;
                        cond.field = c_json["field"].get<std::string>();
                        cond.op = c_json["op"].get<std::string>();
                        cond.value = c_json["value"].get<double>();
                        r.conditions.push_back(std::move(cond));
                    }
                }
                if (r_json.contains("actions") && r_json["actions"].is_object()) {
                    const auto& act = r_json["actions"];
                    r.actions.profile = act["profile"].get<std::string>();
                    r.actions.mode = act["mode"].get<std::string>();
                    r.actions.rekey_interval_seconds = act["rekey_interval_seconds"].get<std::uint32_t>();
                    r.actions.session_lifetime_seconds = act["session_lifetime_seconds"].get<std::uint32_t>();
                }
                parsed_rules.push_back(std::move(r));
            }
        }

        RuleActions def_act;
        if (root.contains("default") && root["default"].is_object()) {
            const auto& act = root["default"];
            def_act.profile = act["profile"].get<std::string>();
            def_act.mode = act["mode"].get<std::string>();
            def_act.rekey_interval_seconds = act["rekey_interval_seconds"].get<std::uint32_t>();
            def_act.session_lifetime_seconds = act["session_lifetime_seconds"].get<std::uint32_t>();
        } else {
            def_act.profile = "Standard";
            def_act.mode = "Hybrid";
            def_act.rekey_interval_seconds = 3600;
            def_act.session_lifetime_seconds = 7200;
        }

        rules_ = std::move(parsed_rules);
        default_actions_ = std::move(def_act);
        has_loaded_rules_ = true;

        UAV_PQC_LOG_INFO("policy.acpe", "Successfully loaded {} policy rules from JSON", rules_.size());
        return ok();
    } catch (const std::exception& e) {
        return err(ErrorCode::InvalidArgument, std::string("JSON parse error: ") + e.what());
    }
}

// ── load_rules_file ──────────────────────────────────────────────────────────

VoidResult RuleBasedAcpe::load_rules_file(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::in | std::ios::binary);
    if (!f.is_open()) {
        return err(ErrorCode::InvalidArgument, "Failed to open policy rules file: " + filepath);
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    std::string str = ss.str();
    return load_rules_json(ByteSpan{reinterpret_cast<const std::byte*>(str.data()), str.size()});
}

} // namespace uav_pqc::policy
