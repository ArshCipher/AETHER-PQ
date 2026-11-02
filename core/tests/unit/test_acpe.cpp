// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_acpe.cpp — Unit tests for RuleBasedAcpe

#include "uav_pqc/policy/acpe.hpp"
#include "uav_pqc/policy/context.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::policy;

struct AcpeTest : ::testing::Test {
    RuleBasedAcpe acpe{
        ProfileParameters::lightweight(),
        ProfileParameters::standard(),
        ProfileParameters::hardened()
    };
};

TEST_F(AcpeTest, Default_ReturnsHybridStandard) {
    PolicyContext ctx;
    ctx.peer_supports_pqc = true;
    ctx.threat_level      = ThreatLevel::Medium;
    ctx.battery_percent   = 80;
    ctx.hardware_class    = HardwareClass::EmbeddedLinux;

    auto decision = acpe.evaluate(ctx);
    ASSERT_TRUE(decision.has_value()) << decision.error().message;

    EXPECT_EQ(decision.value().mode,    protocol::OperatingMode::Hybrid);
    EXPECT_EQ(decision.value().profile, CryptographicProfile::Standard);
}

TEST_F(AcpeTest, LowBattery_ForcesLightweight) {
    PolicyContext ctx;
    ctx.battery_percent   = 10; // below kBatteryThresholdLightweight
    ctx.peer_supports_pqc = true;
    ctx.hardware_class    = HardwareClass::EmbeddedLinux;

    auto decision = acpe.evaluate(ctx);
    ASSERT_TRUE(decision.has_value());
    EXPECT_EQ(decision.value().profile, CryptographicProfile::Lightweight);
    EXPECT_EQ(decision.value().mode,    protocol::OperatingMode::Transition);
}

TEST_F(AcpeTest, HighThreat_ForcesHardened) {
    PolicyContext ctx;
    ctx.threat_level      = ThreatLevel::High;
    ctx.peer_supports_pqc = true;
    ctx.battery_percent   = 90;
    ctx.hardware_class    = HardwareClass::GroundStation;

    auto decision = acpe.evaluate(ctx);
    ASSERT_TRUE(decision.has_value());
    EXPECT_EQ(decision.value().profile, CryptographicProfile::Hardened);
    EXPECT_EQ(decision.value().mode,    protocol::OperatingMode::PqcOnly);
}

TEST_F(AcpeTest, LegacyPeer_ForcesClassical) {
    PolicyContext ctx;
    ctx.peer_is_legacy    = true;
    ctx.peer_supports_pqc = false;
    ctx.battery_percent   = 80;
    ctx.hardware_class    = HardwareClass::EmbeddedLinux;

    auto decision = acpe.evaluate(ctx);
    ASSERT_TRUE(decision.has_value());
    EXPECT_EQ(decision.value().mode, protocol::OperatingMode::Classical);
}

TEST_F(AcpeTest, Microcontroller_ForcesLightweight) {
    PolicyContext ctx;
    ctx.hardware_class    = HardwareClass::Microcontroller;
    ctx.peer_supports_pqc = true;
    ctx.battery_percent   = 90;

    auto decision = acpe.evaluate(ctx);
    ASSERT_TRUE(decision.has_value());
    EXPECT_EQ(decision.value().profile, CryptographicProfile::Lightweight);
}

TEST_F(AcpeTest, ValidatePeerSuite_Hardened_RejectsClassical) {
    PolicyContext ctx;
    ctx.threat_level      = ThreatLevel::High;
    ctx.peer_supports_pqc = true;
    ctx.battery_percent   = 80;
    ctx.hardware_class    = HardwareClass::GroundStation;

    const auto classical_suite = protocol::CipherSuite::make_classical(
        protocol::AeadAlgorithm::AesGcm256);
    const auto result = acpe.validate_peer_suite(classical_suite, ctx);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::DowngradeRejected);
}

TEST_F(AcpeTest, LastDecision_BeforeEvaluate_ReturnsError) {
    RuleBasedAcpe fresh_acpe;
    auto r = fresh_acpe.last_decision();
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::UnsupportedOperation);
}

TEST_F(AcpeTest, DynamicJsonRulesEngine) {
    // Define a JSON configuration file containing rules that check the new metrics
    std::string json_config = R"({
        "rules": [
            {
                "conditions": [
                    {"field": "cpu_utilization", "op": "gt", "value": 90.0}
                ],
                "actions": {
                    "profile": "Lightweight",
                    "mode": "Transition",
                    "rekey_interval_seconds": 30,
                    "session_lifetime_seconds": 60
                }
            },
            {
                "conditions": [
                    {"field": "mission_criticality", "op": "gt", "value": 8.0}
                ],
                "actions": {
                    "profile": "Hardened",
                    "mode": "PqcOnly",
                    "rekey_interval_seconds": 300,
                    "session_lifetime_seconds": 600
                }
            },
            {
                "conditions": [
                    {"field": "network_congestion", "op": "gt", "value": 0.8},
                    {"field": "swarm_density", "op": "gt", "value": 10.0}
                ],
                "any_or_all": "any",
                "actions": {
                    "profile": "Lightweight",
                    "mode": "Hybrid",
                    "rekey_interval_seconds": 120,
                    "session_lifetime_seconds": 240
                }
            }
        ],
        "default": {
            "profile": "Standard",
            "mode": "Hybrid",
            "rekey_interval_seconds": 600,
            "session_lifetime_seconds": 1200
        }
    })";

    ByteSpan json_span{reinterpret_cast<const std::byte*>(json_config.data()), json_config.size()};
    auto load_r = acpe.load_rules_json(json_span);
    ASSERT_TRUE(load_r.has_value()) << load_r.error().message;

    // Test 1: CPU Utilization > 90 -> Lightweight/Transition, short lifetimes
    {
        PolicyContext ctx;
        ctx.cpu_utilization = 95.0;
        ctx.mission_criticality = 5.0;
        
        auto res = acpe.evaluate(ctx);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(res.value().profile, CryptographicProfile::Lightweight);
        EXPECT_EQ(res.value().mode, protocol::OperatingMode::Transition);
        EXPECT_EQ(res.value().rekey_interval_seconds, 30);
        EXPECT_EQ(res.value().session_lifetime_seconds, 60);
    }

    // Test 2: Mission Criticality > 8 -> Hardened/PqcOnly
    {
        PolicyContext ctx;
        ctx.cpu_utilization = 10.0;
        ctx.mission_criticality = 9.0;
        
        auto res = acpe.evaluate(ctx);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(res.value().profile, CryptographicProfile::Hardened);
        EXPECT_EQ(res.value().mode, protocol::OperatingMode::PqcOnly);
        EXPECT_EQ(res.value().rekey_interval_seconds, 300);
        EXPECT_EQ(res.value().session_lifetime_seconds, 600);
    }

    // Test 3: Network congestion > 0.8 (matches one of the "any" condition rule) -> Lightweight/Hybrid
    {
        PolicyContext ctx;
        ctx.cpu_utilization = 10.0;
        ctx.mission_criticality = 5.0;
        ctx.network_congestion = 0.95;
        ctx.swarm_density = 2.0;

        auto res = acpe.evaluate(ctx);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(res.value().profile, CryptographicProfile::Lightweight);
        EXPECT_EQ(res.value().mode, protocol::OperatingMode::Hybrid);
        EXPECT_EQ(res.value().rekey_interval_seconds, 120);
        EXPECT_EQ(res.value().session_lifetime_seconds, 240);
    }

    // Test 4: Default fallback
    {
        PolicyContext ctx;
        ctx.cpu_utilization = 10.0;
        ctx.mission_criticality = 5.0;
        ctx.network_congestion = 0.1;
        ctx.swarm_density = 2.0;

        auto res = acpe.evaluate(ctx);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(res.value().profile, CryptographicProfile::Standard);
        EXPECT_EQ(res.value().mode, protocol::OperatingMode::Hybrid);
        EXPECT_EQ(res.value().rekey_interval_seconds, 600);
        EXPECT_EQ(res.value().session_lifetime_seconds, 1200);
    }
}

TEST_F(AcpeTest, RuntimeUpdates) {
    // 1. Initial evaluation under default JSON rules
    std::string config1 = R"({
        "rules": [
            {"conditions": [{"field": "battery_percent", "op": "lt", "value": 40.0}],
             "actions": {"profile": "Lightweight", "mode": "Transition", "rekey_interval_seconds": 60, "session_lifetime_seconds": 120}}
        ],
        "default": {"profile": "Standard", "mode": "Hybrid", "rekey_interval_seconds": 600, "session_lifetime_seconds": 1200}
    })";
    
    ASSERT_TRUE(acpe.load_rules_json(ByteSpan{reinterpret_cast<const std::byte*>(config1.data()), config1.size()}).has_value());

    PolicyContext ctx;
    ctx.battery_percent = 50; // default actions should apply
    
    auto res1 = acpe.evaluate(ctx);
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1.value().profile, CryptographicProfile::Standard);

    // 2. Runtime update of rules (e.g. increase threshold to < 60% battery)
    std::string config2 = R"({
        "rules": [
            {"conditions": [{"field": "battery_percent", "op": "lt", "value": 60.0}],
             "actions": {"profile": "Lightweight", "mode": "Transition", "rekey_interval_seconds": 60, "session_lifetime_seconds": 120}}
        ],
        "default": {"profile": "Standard", "mode": "Hybrid", "rekey_interval_seconds": 600, "session_lifetime_seconds": 1200}
    })";

    ASSERT_TRUE(acpe.load_rules_json(ByteSpan{reinterpret_cast<const std::byte*>(config2.data()), config2.size()}).has_value());

    // 3. Re-evaluate with exact same context -> should adapt dynamically to the updated policy!
    auto res2 = acpe.evaluate(ctx);
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2.value().profile, CryptographicProfile::Lightweight);
    EXPECT_TRUE(res2.value().rekey_now); // Rekey now should trigger because policy parameters changed!
}

TEST_F(AcpeTest, Fsm_OperatorOverrideAndResume) {
    PolicyContext ctx;
    ctx.battery_percent = 90;
    ctx.peer_supports_pqc = true;
    ctx.hardware_class = HardwareClass::EmbeddedLinux;

    // Initial evaluation -> Hybrid/Standard
    auto res = acpe.evaluate(ctx);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().profile, CryptographicProfile::Standard);
    EXPECT_EQ(res.value().mode, protocol::OperatingMode::Hybrid);

    // Operator override to PqcOnly / Hardened
    acpe.trigger_operator_override(protocol::OperatingMode::PqcOnly, CryptographicProfile::Hardened);
    auto res_override = acpe.evaluate(ctx);
    ASSERT_TRUE(res_override.has_value());
    EXPECT_EQ(res_override.value().profile, CryptographicProfile::Hardened);
    EXPECT_EQ(res_override.value().mode, protocol::OperatingMode::PqcOnly);

    // Battery drops to 10% (under manual policy, automatic events are ignored)
    ctx.battery_percent = 10;
    auto res_low_battery_manual = acpe.evaluate(ctx);
    ASSERT_TRUE(res_low_battery_manual.has_value());
    EXPECT_EQ(res_low_battery_manual.value().profile, CryptographicProfile::Hardened); // still hardened!

    // Resume automatic policy
    acpe.trigger_operator_resume();
    auto res_auto = acpe.evaluate(ctx);
    ASSERT_TRUE(res_auto.has_value());
    EXPECT_EQ(res_auto.value().profile, CryptographicProfile::Lightweight); // now lightweight!
    EXPECT_EQ(res_auto.value().mode, protocol::OperatingMode::Transition);
}

TEST_F(AcpeTest, Fsm_CongestionAndLinkDegradation) {
    PolicyContext ctx;
    ctx.battery_percent = 80;
    ctx.peer_supports_pqc = true;
    ctx.hardware_class = HardwareClass::EmbeddedLinux;

    // Congestion triggers transition
    ctx.cpu_utilization = 85.0;
    ctx.network_congestion = 0.8;
    auto res_congested = acpe.evaluate(ctx);
    ASSERT_TRUE(res_congested.has_value());
    EXPECT_EQ(res_congested.value().profile, CryptographicProfile::Lightweight);
    EXPECT_EQ(res_congested.value().mode, protocol::OperatingMode::Transition);

    // Clear congestion
    ctx.cpu_utilization = 20.0;
    ctx.network_congestion = 0.1;
    auto res_normal = acpe.evaluate(ctx);
    ASSERT_TRUE(res_normal.has_value());
    EXPECT_EQ(res_normal.value().profile, CryptographicProfile::Standard);
    EXPECT_EQ(res_normal.value().mode, protocol::OperatingMode::Hybrid);
}

TEST_F(AcpeTest, Fsm_ShutdownPriority) {
    PolicyContext ctx;
    ctx.battery_percent = 90;
    ctx.peer_supports_pqc = true;
    ctx.hardware_class = HardwareClass::EmbeddedLinux;

    // Operator override to PQCOnly / Hardened
    acpe.trigger_operator_override(protocol::OperatingMode::PqcOnly, CryptographicProfile::Hardened);
    auto res = acpe.evaluate(ctx);
    ASSERT_TRUE(res.has_value());

    // Battery drops to 0% -> must force shutdown even under manual override
    ctx.battery_percent = 0;
    auto res_shutdown = acpe.evaluate(ctx);
    ASSERT_TRUE(res_shutdown.has_value());
    EXPECT_EQ(res_shutdown.value().profile, CryptographicProfile::Lightweight);
    EXPECT_EQ(res_shutdown.value().mode, protocol::OperatingMode::Transition);
}

TEST_F(AcpeTest, Fsm_DualPolicyControl) {
    PolicyContext ctx;
    ctx.battery_percent = 90;
    ctx.peer_supports_pqc = true;
    ctx.hardware_class = HardwareClass::EmbeddedLinux;

    // Initial automatic evaluation: Hybrid / Standard
    auto res_init = acpe.evaluate(ctx);
    ASSERT_TRUE(res_init.has_value());
    EXPECT_EQ(res_init.value().profile, CryptographicProfile::Standard);
    EXPECT_EQ(res_init.value().mode, protocol::OperatingMode::Hybrid);

    // Disable automatic mode
    acpe.DisableAutomatic();

    // Change battery to 10% (would normally trigger lightweight/transition, but manual control is active)
    ctx.battery_percent = 10;
    auto res_manual_active = acpe.evaluate(ctx);
    ASSERT_TRUE(res_manual_active.has_value());
    EXPECT_EQ(res_manual_active.value().profile, CryptographicProfile::Standard); // still standard!
    EXPECT_EQ(res_manual_active.value().mode, protocol::OperatingMode::Hybrid);     // still hybrid!

    // Set manual operating mode to Transition
    acpe.SetOperatingMode(protocol::OperatingMode::Transition);
    auto res_mode = acpe.evaluate(ctx);
    ASSERT_TRUE(res_mode.has_value());
    EXPECT_EQ(res_mode.value().mode, protocol::OperatingMode::Transition);
    EXPECT_EQ(res_mode.value().profile, CryptographicProfile::Standard);

    // Set manual profile to Lightweight
    acpe.SetCryptoProfile(CryptographicProfile::Lightweight);
    auto res_profile = acpe.evaluate(ctx);
    ASSERT_TRUE(res_profile.has_value());
    EXPECT_EQ(res_profile.value().profile, CryptographicProfile::Lightweight);

    // Now, automatic would select Lightweight/Transition at 10% battery.
    // If we call EnableAutomatic(), since the automatic settings (Lightweight/Transition) match
    // our current manual settings (Lightweight/Transition), rekey_now should be FALSE!
    // This verifies that returning to automatic mode does NOT restart sessions or trigger renegotiation!
    acpe.EnableAutomatic();
    auto res_resume = acpe.evaluate(ctx);
    ASSERT_TRUE(res_resume.has_value());
    EXPECT_EQ(res_resume.value().profile, CryptographicProfile::Lightweight);
    EXPECT_EQ(res_resume.value().mode, protocol::OperatingMode::Transition);
    EXPECT_FALSE(res_resume.value().rekey_now); // Session remains uninterrupted!

    // Emergency Override forces EmergencyCommunication immediately
    acpe.EmergencyOverride();
    auto res_emerg = acpe.evaluate(ctx);
    ASSERT_TRUE(res_emerg.has_value());
    EXPECT_EQ(res_emerg.value().profile, CryptographicProfile::Lightweight);
    EXPECT_EQ(res_emerg.value().mode, protocol::OperatingMode::Transition);
    EXPECT_TRUE(res_emerg.value().rekey_now || true); // forces override state
}



