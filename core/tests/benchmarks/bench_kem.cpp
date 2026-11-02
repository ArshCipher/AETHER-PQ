// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// bench_kem.cpp — Benchmark for ML-KEM-512, ML-KEM-768, ML-KEM-1024, X25519

#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/x25519.hpp"
#include <benchmark/benchmark.h>
#include "bench_resources.hpp"

using namespace uav_pqc::crypto;

static void BM_MlKem512_KeyGen(benchmark::State& state) {
    MlKem kem(MlKem::Level::Kem512);
    auto before = capture_resources();
    for (auto _ : state) {
        auto kp = kem.generate_keypair();
        benchmark::DoNotOptimize(kp);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(KemKeyPair)));
}
BENCHMARK(BM_MlKem512_KeyGen);

static void BM_MlKem768_KeyGen(benchmark::State& state) {
    MlKem kem(MlKem::Level::Kem768);
    auto before = capture_resources();
    for (auto _ : state) {
        auto kp = kem.generate_keypair();
        benchmark::DoNotOptimize(kp);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(KemKeyPair)));
}
BENCHMARK(BM_MlKem768_KeyGen);

static void BM_MlKem1024_KeyGen(benchmark::State& state) {
    MlKem kem(MlKem::Level::Kem1024);
    auto before = capture_resources();
    for (auto _ : state) {
        auto kp = kem.generate_keypair();
        benchmark::DoNotOptimize(kp);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(KemKeyPair)));
}
BENCHMARK(BM_MlKem1024_KeyGen);

static void BM_X25519_KeyGen(benchmark::State& state) {
    X25519Kem kem;
    auto before = capture_resources();
    for (auto _ : state) {
        auto kp = kem.generate_keypair();
        benchmark::DoNotOptimize(kp);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(KemKeyPair)));
}
BENCHMARK(BM_X25519_KeyGen);

static void BM_MlKem768_EncapDecap(benchmark::State& state) {
    MlKem kem(MlKem::Level::Kem768);
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
BENCHMARK(BM_MlKem768_EncapDecap);
