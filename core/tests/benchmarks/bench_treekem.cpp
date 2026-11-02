// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file bench_treekem.cpp
 * @brief Scalability benchmarks for TreeKEM Join, Leave, and ProcessUpdate.
 */

#include "uav_pqc/group/tree_kem.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include <benchmark/benchmark.h>
#include <vector>
#include <memory>
#include "bench_resources.hpp"

using namespace uav_pqc;
using namespace uav_pqc::group;

namespace {

// Helper to pre-populate a tree with N members
std::unique_ptr<ITreeKem> setup_tree_with_members(std::uint32_t N,
                                                  const protocol::CipherSuite& suite,
                                                  std::vector<crypto::KemKeyPair>& member_keypairs) {
    auto tk = make_tree_kem(suite);
    crypto::MlKem mlkem(suite.kem_level);

    for (std::uint32_t i = 0; i < N; ++i) {
        auto kp = mlkem.generate_keypair().value();
        member_keypairs.push_back(std::move(kp));

        NodeId id{};
        id[0] = static_cast<std::byte>(i & 0xFF);
        id[1] = static_cast<std::byte>((i >> 8) & 0xFF);

        SwarmMember member{
            .node_id = id,
            .leaf_key = member_keypairs.back().public_key,
            .leaf_index = i,
            .joined_at_ms = 1000 + i
        };

        auto r = tk->add_member(member, suite);
        (void)r;
    }
    return tk;
}

} // namespace

// ── Benchmark Group Rekey / Member Add Scalability ───────────────────────────

static void BM_TreeKem_AddMember_Scale(benchmark::State& state) {
    const std::uint32_t N = static_cast<std::uint32_t>(state.range(0));
    auto suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    crypto::MlKem mlkem(suite.kem_level);

    auto before = capture_resources();
    for (auto _ : state) {
        state.PauseTiming();
        std::vector<crypto::KemKeyPair> keypairs;
        auto tk = setup_tree_with_members(N, suite, keypairs);

        auto next_kp = mlkem.generate_keypair().value();
        NodeId next_id{};
        next_id[0] = std::byte{0xFF};
        SwarmMember next_member{
            .node_id = next_id,
            .leaf_key = next_kp.public_key,
            .leaf_index = N,
            .joined_at_ms = 9999
        };
        state.ResumeTiming();

        auto r = tk->add_member(next_member, suite);
        benchmark::DoNotOptimize(r);
    }
    auto after = capture_resources();
    // SessionObjectSizeBytes reports the ITreeKem implementation object size
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(SwarmMember)));
}
BENCHMARK(BM_TreeKem_AddMember_Scale)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Arg(128)->Unit(benchmark::kMicrosecond);

// ── Benchmark Update Processing Scalability ──────────────────────────────────

static void BM_TreeKem_ProcessUpdate_Scale(benchmark::State& state) {
    const std::uint32_t N = static_cast<std::uint32_t>(state.range(0));
    auto suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    crypto::MlKem mlkem(suite.kem_level);

    auto before = capture_resources();
    for (auto _ : state) {
        state.PauseTiming();
        std::vector<crypto::KemKeyPair> keypairs;
        auto tk = setup_tree_with_members(N, suite, keypairs);

        // Add one more member to generate a GroupKeyUpdate
        auto next_kp = mlkem.generate_keypair().value();
        NodeId next_id{};
        next_id[0] = std::byte{0xFF};
        SwarmMember next_member{
            .node_id = next_id,
            .leaf_key = next_kp.public_key,
            .leaf_index = N,
            .joined_at_ms = 9999
        };
        auto update = tk->add_member(next_member, suite).value();

        // Node index we will use to process the update (e.g. member 0)
        NodeId my_node_id = keypairs[0].public_key.data[0] == std::byte{0} ? NodeId{} : NodeId{};
        my_node_id[0] = std::byte{0}; // matches setting in setup_tree_with_members
        state.ResumeTiming();

        auto r = tk->process_update(update, my_node_id, keypairs[0].private_key);
        benchmark::DoNotOptimize(r);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(SwarmMember)));
}
BENCHMARK(BM_TreeKem_ProcessUpdate_Scale)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Arg(128)->Unit(benchmark::kMicrosecond);
