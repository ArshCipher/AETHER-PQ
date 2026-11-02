// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// bench_hybrid_kem.cpp — Benchmark for Hybrid KEM (ML-KEM-768 + X25519)

#include "uav_pqc/crypto/hybrid_kem.hpp"
#include <benchmark/benchmark.h>
#include "bench_resources.hpp"

using namespace uav_pqc::crypto;

static void BM_HybridKem_KeyGen(benchmark::State& state) {
    HybridKem kem("benchmarking context");
    auto before = capture_resources();
    for (auto _ : state) {
        auto kp = kem.generate_keypair();
        benchmark::DoNotOptimize(kp);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(KemKeyPair)));
}
BENCHMARK(BM_HybridKem_KeyGen);

static void BM_HybridKem_EncapDecap(benchmark::State& state) {
    HybridKem kem("benchmarking context");
    auto kp = kem.generate_keypair().value();
    auto before = capture_resources();
    for (auto _ : state) {
        auto enc = kem.encapsulate(kp.public_key).value();
        auto dec = kem.decapsulate(kp.private_key, enc.ciphertext).value();
        benchmark::DoNotOptimize(enc);
        benchmark::DoNotOptimize(dec);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
}
BENCHMARK(BM_HybridKem_EncapDecap);
