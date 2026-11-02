// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// bench_aead.cpp — Benchmark for AES-GCM and ChaCha20-Poly1305

#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/crypto/chacha20_poly1305.hpp"
#include <benchmark/benchmark.h>
#include <array>
#include "bench_resources.hpp"

using namespace uav_pqc;
using namespace uav_pqc::crypto;

static void BM_AesGcm256_Encrypt(benchmark::State& state) {
    AesGcm aead(AesKeyLen::Aes256);
    AeadKey key;
    key.data.resize(32);
    std::memset(key.data.data(), 0x42, 32);
    std::array<std::byte, 12> nonce{};
    Bytes pt(static_cast<std::size_t>(state.range(0)), std::byte{0x01});
    Bytes aad(16, std::byte{0x02});

    auto before = capture_resources();
    for (auto _ : state) {
        auto ct = aead.encrypt(key, ByteSpan{nonce.data(), nonce.size()},
                               ByteSpan{pt.data(), pt.size()},
                               ByteSpan{aad.data(), aad.size()});
        benchmark::DoNotOptimize(ct);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
    state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_AesGcm256_Encrypt)->RangeMultiplier(4)->Range(128, 4096);

static void BM_ChaCha20Poly1305_Encrypt(benchmark::State& state) {
    ChaCha20Poly1305 aead;
    AeadKey key;
    key.data.resize(32);
    std::memset(key.data.data(), 0x42, 32);
    std::array<std::byte, 12> nonce{};
    Bytes pt(static_cast<std::size_t>(state.range(0)), std::byte{0x01});
    Bytes aad(16, std::byte{0x02});

    auto before = capture_resources();
    for (auto _ : state) {
        auto ct = aead.encrypt(key, ByteSpan{nonce.data(), nonce.size()},
                               ByteSpan{pt.data(), pt.size()},
                               ByteSpan{aad.data(), aad.size()});
        benchmark::DoNotOptimize(ct);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
    state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_ChaCha20Poly1305_Encrypt)->RangeMultiplier(4)->Range(128, 4096);
