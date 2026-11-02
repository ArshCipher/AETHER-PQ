// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#include <benchmark/benchmark.h>
#include "uav_pqc/policy/acpe.hpp"
#include "uav_pqc/policy/context.hpp"
#include "bench_resources.hpp"

using namespace uav_pqc;
using namespace uav_pqc::policy;

static const std::string kJsonRules = R"({
    "rules": [
        {"conditions": [{"field": "cpu_utilization", "op": "gt", "value": 85.0}],
         "actions": {"profile": "Lightweight", "mode": "Transition", "rekey_interval_seconds": 60, "session_lifetime_seconds": 120}},
        {"conditions": [{"field": "battery_percent", "op": "lt", "value": 20.0}],
         "actions": {"profile": "Lightweight", "mode": "Transition", "rekey_interval_seconds": 120, "session_lifetime_seconds": 240}},
        {"conditions": [{"field": "mission_criticality", "op": "gte", "value": 8.0}],
         "actions": {"profile": "Hardened", "mode": "PqcOnly", "rekey_interval_seconds": 300, "session_lifetime_seconds": 600}},
        {"any_or_all": "any", "conditions": [
            {"field": "network_congestion", "op": "gt", "value": 0.75},
            {"field": "swarm_density",      "op": "gt", "value": 20.0}],
         "actions": {"profile": "Lightweight", "mode": "Hybrid", "rekey_interval_seconds": 180, "session_lifetime_seconds": 360}},
        {"conditions": [{"field": "mobility", "op": "gt", "value": 25.0}],
         "actions": {"profile": "Standard", "mode": "Hybrid", "rekey_interval_seconds": 600, "session_lifetime_seconds": 1200}}
    ],
    "default": {"profile": "Standard", "mode": "Hybrid", "rekey_interval_seconds": 600, "session_lifetime_seconds": 1200}
})";

static void BM_AcpeEvaluate_StaticRules(benchmark::State& state) {
    RuleBasedAcpe acpe;
    PolicyContext ctx;
    ctx.hardware_class = HardwareClass::EmbeddedLinux;
    ctx.battery_percent = 75;
    ctx.threat_level = ThreatLevel::Medium;
    ctx.peer_supports_pqc = true;
    ctx.mission_criticality = 5.0;
    ctx.network_congestion = 0.2;
    ctx.swarm_density = 5.0;
    ctx.cpu_utilization = 30.0;
    ctx.speed_m_s = 10.0f;

    auto before = capture_resources();
    for (auto _ : state) {
        auto res = acpe.evaluate(ctx);
        benchmark::DoNotOptimize(res);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(PolicyContext)));
}
BENCHMARK(BM_AcpeEvaluate_StaticRules);

static void BM_AcpeEvaluate_JsonRules(benchmark::State& state) {
    RuleBasedAcpe acpe;
    ByteSpan json_span{reinterpret_cast<const std::byte*>(kJsonRules.data()), kJsonRules.size()};
    (void)acpe.load_rules_json(json_span);

    PolicyContext ctx;
    ctx.hardware_class = HardwareClass::EmbeddedLinux;
    ctx.battery_percent = 75;
    ctx.threat_level = ThreatLevel::Medium;
    ctx.peer_supports_pqc = true;
    ctx.mission_criticality = 5.0;
    ctx.network_congestion = 0.2;
    ctx.swarm_density = 5.0;
    ctx.cpu_utilization = 30.0;
    ctx.speed_m_s = 10.0f;

    auto before = capture_resources();
    for (auto _ : state) {
        auto res = acpe.evaluate(ctx);
        benchmark::DoNotOptimize(res);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(PolicyContext)));
}
BENCHMARK(BM_AcpeEvaluate_JsonRules);

static void BM_AcpeEvaluate_JsonRules_RuleMatch(benchmark::State& state) {
    RuleBasedAcpe acpe;
    ByteSpan json_span{reinterpret_cast<const std::byte*>(kJsonRules.data()), kJsonRules.size()};
    (void)acpe.load_rules_json(json_span);

    // Trigger rule 3 (mission_criticality >= 8.0 → Hardened/PqcOnly)
    PolicyContext ctx;
    ctx.hardware_class = HardwareClass::GroundStation;
    ctx.battery_percent = 90;
    ctx.peer_supports_pqc = true;
    ctx.mission_criticality = 9.5;
    ctx.network_congestion = 0.1;
    ctx.swarm_density = 3.0;
    ctx.cpu_utilization = 20.0;
    ctx.speed_m_s = 0.0f;

    auto before = capture_resources();
    for (auto _ : state) {
        auto res = acpe.evaluate(ctx);
        benchmark::DoNotOptimize(res);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(PolicyContext)));
}
BENCHMARK(BM_AcpeEvaluate_JsonRules_RuleMatch);

static void BM_AcpeValidatePeerSuite_Hardened(benchmark::State& state) {
    RuleBasedAcpe acpe;
    PolicyContext ctx;
    ctx.threat_level = ThreatLevel::High;
    ctx.peer_supports_pqc = true;
    ctx.battery_percent = 90;
    ctx.hardware_class = HardwareClass::GroundStation;

    auto pqc_suite = protocol::CipherSuite::make_pqc_only(
        crypto::MlKem::Level::Kem1024,
        crypto::MlDsa::Level::Dsa87,
        protocol::AeadAlgorithm::AesGcm256);

    auto before = capture_resources();
    for (auto _ : state) {
        auto res = acpe.validate_peer_suite(pqc_suite, ctx);
        benchmark::DoNotOptimize(res);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
}
BENCHMARK(BM_AcpeValidatePeerSuite_Hardened);
