// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// bench_hkdf.cpp — Benchmark for HKDF-SHA256 and HKDF-SHA512

#include "uav_pqc/crypto/hkdf.hpp"
#include <benchmark/benchmark.h>
#include "bench_resources.hpp"

using namespace uav_pqc;
using namespace uav_pqc::crypto;

static void BM_HkdfSha256_Derive(benchmark::State& state) {
    Hkdf hkdf(HkdfHash::Sha256);
    Bytes salt(32, std::byte{0x01});
    Bytes ikm(32, std::byte{0x02});
    Bytes info(16, std::byte{0x03});

    auto before = capture_resources();
    for (auto _ : state) {
        auto out = hkdf.derive(ByteSpan{salt.data(), salt.size()},
                               ByteSpan{ikm.data(), ikm.size()},
                               ByteSpan{info.data(), info.size()}, 32);
        benchmark::DoNotOptimize(out);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
}
BENCHMARK(BM_HkdfSha256_Derive);

static void BM_HkdfSha512_Derive(benchmark::State& state) {
    Hkdf hkdf(HkdfHash::Sha512);
    Bytes salt(64, std::byte{0x01});
    Bytes ikm(64, std::byte{0x02});
    Bytes info(16, std::byte{0x03});

    auto before = capture_resources();
    for (auto _ : state) {
        auto out = hkdf.derive(ByteSpan{salt.data(), salt.size()},
                               ByteSpan{ikm.data(), ikm.size()},
                               ByteSpan{info.data(), info.size()}, 64);
        benchmark::DoNotOptimize(out);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
}
BENCHMARK(BM_HkdfSha512_Derive);
