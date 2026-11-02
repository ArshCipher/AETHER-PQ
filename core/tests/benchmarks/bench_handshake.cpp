// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file bench_handshake.cpp
 * @brief Handshake latency benchmarks — all four operating modes.
 *
 * Each benchmark measures the complete two-party session establishment:
 *   Initiator keygen → send ClientHello → Responder encap → send ServerHello →
 *   Initiator decap → key derivation → mutual auth → Finished → Session ready.
 *
 * Certificate infrastructure is minimal (self-signed dummy DER matching the
 * format expected by Certificate::from_der).  The auth path exercises the
 * ML-DSA / ECDSA signing and parsing code but uses freshly generated keys.
 *
 * Benchmarks:
 *   BM_Handshake_Classical          — X25519 + HKDF-SHA256 + AES-256-GCM
 *   BM_Handshake_Transition_Kem768  — ML-KEM-768 + HKDF-SHA256 + AES-256-GCM
 *   BM_Handshake_Hybrid             — ML-KEM-768||X25519 + HKDF-SHA256 + AES-256-GCM
 *   BM_Handshake_PqcOnly_Kem1024    — ML-KEM-1024 + HKDF-SHA512 + AES-256-GCM
 *
 *   BM_KeyDerivation_Classical       — HKDF extract + 5×expand from 32-byte IKM
 *   BM_KeyDerivation_Hybrid          — HKDF extract + 5×expand from 32-byte IKM
 *
 *   BM_KemOnly_X25519_EncapDecap     — KEM primitive in isolation
 *   BM_KemOnly_MlKem768_EncapDecap   — KEM primitive in isolation
 *   BM_KemOnly_Hybrid_EncapDecap     — KEM primitive in isolation
 *   BM_KemOnly_MlKem1024_EncapDecap  — KEM primitive in isolation
 */

#include "uav_pqc/protocol/session_establishment.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/x25519.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/crypto/hybrid_kem.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <benchmark/benchmark.h>
#include <vector>

using namespace uav_pqc;
using namespace uav_pqc::protocol;
using namespace uav_pqc::crypto;

// ─────────────────────────────────────────────────────────────────────────────
// Certificate factory — shared between benchmarks
//
// Produces a minimal DER blob accepted by identity::Certificate::from_der.
// Keys are generated once per benchmark fixture (not per iteration).
// ─────────────────────────────────────────────────────────────────────────────

namespace {

struct BenchKeys {
    DsaPublicKey  mldsa_pub;
    Bytes         mldsa_priv_bytes; ///< raw bytes — reconstructed into SecureBytes per config
    DsaPublicKey  ecdsa_pub;
    Bytes         ecdsa_priv_bytes;
};

BenchKeys make_bench_keys() {
    MlDsa mldsa(MlDsa::Level::Dsa65);
    auto ml = mldsa.generate_keypair().value();

    EcdsaP256 ecdsa;
    auto ec = ecdsa.generate_keypair().value();

    BenchKeys bk;
    bk.mldsa_pub        = std::move(ml.public_key);
    bk.mldsa_priv_bytes.assign(ml.private_key.data.bytes().begin(),
                                ml.private_key.data.bytes().end());
    bk.ecdsa_pub        = std::move(ec.public_key);
    bk.ecdsa_priv_bytes.assign(ec.private_key.data.bytes().begin(),
                                ec.private_key.data.bytes().end());
    return bk;
}

/// Build a minimal self-signed DER certificate blob.
Bytes make_dummy_cert(const BenchKeys& keys, bool is_initiator) {
    Bytes cert;
    cert.reserve(2048);

    // SEQUENCE header (length placeholder filled later)
    cert.push_back(std::byte{0x30});
    cert.push_back(std::byte{0x82});
    cert.push_back(std::byte{0x00}); // high byte of length
    cert.push_back(std::byte{0x00}); // low byte of length

    // UTF8String name (12 bytes)
    cert.push_back(std::byte{0x0C});
    cert.push_back(std::byte{12});
    const char* name = "UAV-PQC-Node";
    for (int i = 0; i < 12; ++i) cert.push_back(static_cast<std::byte>(name[i]));

    // subject NodeID (OCTET STRING, 16 bytes)
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{16});
    cert.insert(cert.end(), 16, is_initiator ? std::byte{0x01} : std::byte{0x02});

    // issuer NodeID (OCTET STRING, 16 bytes)
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{16});
    cert.insert(cert.end(), 16, std::byte{0xCA});

    // not_before (INTEGER, 8 bytes = 0)
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{8});
    cert.insert(cert.end(), 8, std::byte{0x00});

    // not_after (INTEGER, 8 bytes = 0xFF = effectively never)
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{8});
    cert.insert(cert.end(), 8, std::byte{0xFF});

    // key_type = Hybrid (0x05) as INTEGER(1)
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{1});
    cert.push_back(std::byte{0x05});

    // ECDSA public key (OCTET STRING, 65 bytes)
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{65});
    cert.insert(cert.end(),
                keys.ecdsa_pub.data.begin(),
                keys.ecdsa_pub.data.end());

    // ML-DSA public key (OCTET STRING, long form)
    const auto& mlpub = keys.mldsa_pub.data;
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{0x82});
    cert.push_back(static_cast<std::byte>((mlpub.size() >> 8) & 0xFF));
    cert.push_back(static_cast<std::byte>(mlpub.size() & 0xFF));
    cert.insert(cert.end(), mlpub.begin(), mlpub.end());

    // Fix up SEQUENCE length
    const std::uint16_t body_len = static_cast<std::uint16_t>(cert.size() - 4);
    cert[2] = static_cast<std::byte>((body_len >> 8) & 0xFF);
    cert[3] = static_cast<std::byte>(body_len & 0xFF);

    return cert;
}

EstablishmentConfig make_config(const BenchKeys& keys, bool is_initiator,
                                std::vector<OperatingMode> modes) {
    HandshakeConfig hc;
    hc.offered_modes = std::move(modes);
    hc.our_node_id[0] = is_initiator ? std::byte{0x01} : std::byte{0x02};

    // Reconstruct DsaPrivateKey from raw bytes (SecureBytes is non-copyable)
    hc.our_ml_dsa_private_key.data = SecureBytes(Bytes(keys.mldsa_priv_bytes));
    hc.our_dsa_private_key.data    = SecureBytes(Bytes(keys.ecdsa_priv_bytes));

    // Certificate
    hc.our_certificate = make_dummy_cert(keys, is_initiator);
    hc.trusted_ca_certs.push_back(hc.our_certificate); // self-trust for bench

    EstablishmentConfig ec;
    ec.handshake = std::move(hc);
    return ec;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core helper: run one complete two-party handshake synchronously
// ─────────────────────────────────────────────────────────────────────────────

void run_exchange(std::unique_ptr<ISessionEstablisher>& init,
                  std::unique_ptr<ISessionEstablisher>& resp) {
    init->set_send_fn([&](Bytes b) -> VoidResult { return resp->feed_message(b); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { return init->feed_message(b); });
    auto r = init->start();
    (void)r; // errors abort via benchmark state in callers
}

} // namespace

#include "bench_resources.hpp"


// ─────────────────────────────────────────────────────────────────────────────
// Full session establishment benchmarks
// ─────────────────────────────────────────────────────────────────────────────

static void BM_Handshake_Classical(benchmark::State& state) {
    const auto init_keys = make_bench_keys();
    const auto resp_keys = make_bench_keys();
    const std::vector<OperatingMode> modes{OperatingMode::Classical};

    auto before = capture_resources();
    for (auto _ : state) {
        auto init_cfg = make_config(init_keys, true,  modes);
        auto resp_cfg = make_config(resp_keys, false, modes);

        auto init = make_session_establisher(HandshakeRole::Initiator, std::move(init_cfg));
        auto resp = make_session_establisher(HandshakeRole::Responder, std::move(resp_cfg));

        run_exchange(init, resp);

        benchmark::DoNotOptimize(init->state());
        benchmark::DoNotOptimize(resp->state());

        if (state.iterations() == 1) {
            // Verify on first iteration; don't abort the benchmark on failure
            auto r = init->result();
            if (!r) state.SkipWithError(r.error().message.c_str());
        }
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(EstablishmentResult)));
    state.SetLabel("X25519+HKDF-SHA256+AES-256-GCM");
}
BENCHMARK(BM_Handshake_Classical)->Unit(benchmark::kMicrosecond);

static void BM_Handshake_Transition_Kem768(benchmark::State& state) {
    const auto init_keys = make_bench_keys();
    const auto resp_keys = make_bench_keys();
    const std::vector<OperatingMode> modes{OperatingMode::Transition};

    auto before = capture_resources();
    for (auto _ : state) {
        auto init_cfg = make_config(init_keys, true,  modes);
        auto resp_cfg = make_config(resp_keys, false, modes);

        auto init = make_session_establisher(HandshakeRole::Initiator, std::move(init_cfg));
        auto resp = make_session_establisher(HandshakeRole::Responder, std::move(resp_cfg));

        run_exchange(init, resp);
        benchmark::DoNotOptimize(init->state());
        benchmark::DoNotOptimize(resp->state());
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
    state.SetLabel("ML-KEM-768+HKDF-SHA256+AES-256-GCM");
}
BENCHMARK(BM_Handshake_Transition_Kem768)->Unit(benchmark::kMicrosecond);

static void BM_Handshake_Hybrid(benchmark::State& state) {
    const auto init_keys = make_bench_keys();
    const auto resp_keys = make_bench_keys();
    const std::vector<OperatingMode> modes{OperatingMode::Hybrid};

    auto before = capture_resources();
    for (auto _ : state) {
        auto init_cfg = make_config(init_keys, true,  modes);
        auto resp_cfg = make_config(resp_keys, false, modes);

        auto init = make_session_establisher(HandshakeRole::Initiator, std::move(init_cfg));
        auto resp = make_session_establisher(HandshakeRole::Responder, std::move(resp_cfg));

        run_exchange(init, resp);
        benchmark::DoNotOptimize(init->state());
        benchmark::DoNotOptimize(resp->state());
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
    state.SetLabel("ML-KEM-768||X25519+HKDF-SHA256+AES-256-GCM");
}
BENCHMARK(BM_Handshake_Hybrid)->Unit(benchmark::kMicrosecond);

static void BM_Handshake_PqcOnly_Kem1024(benchmark::State& state) {
    const auto init_keys = make_bench_keys();
    const auto resp_keys = make_bench_keys();
    const std::vector<OperatingMode> modes{OperatingMode::PqcOnly};

    auto before = capture_resources();
    for (auto _ : state) {
        auto init_cfg = make_config(init_keys, true,  modes);
        auto resp_cfg = make_config(resp_keys, false, modes);

        auto init = make_session_establisher(HandshakeRole::Initiator, std::move(init_cfg));
        auto resp = make_session_establisher(HandshakeRole::Responder, std::move(resp_cfg));

        run_exchange(init, resp);
        benchmark::DoNotOptimize(init->state());
        benchmark::DoNotOptimize(resp->state());
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
    state.SetLabel("ML-KEM-1024+HKDF-SHA256+AES-256-GCM");
}
BENCHMARK(BM_Handshake_PqcOnly_Kem1024)->Unit(benchmark::kMicrosecond);

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation in isolation
// Measures: HKDF-Extract(32-byte IKM) + 5×HKDF-Expand
// ─────────────────────────────────────────────────────────────────────────────

static void BM_KeyDerivation_Classical(benchmark::State& state) {
    Hkdf hkdf(HkdfHash::Sha256);
    // Fixed 32-byte fake shared secret
    const Bytes ikm(32, std::byte{0xAB});
    const std::size_t key_len = 32;

    auto before = capture_resources();
    for (auto _ : state) {
        auto prk_r = hkdf.extract(ByteSpan{}, ByteSpan{ikm});
        const SecureBytes& prk = prk_r.value();

        auto cw = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|classical|client_write_key|v1"), key_len);
        auto sw = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|classical|server_write_key|v1"), key_len);
        auto fk = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|classical|finished_key|v1"),     32);
        auto cn = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|classical|client_nonce_prefix|v1"), 4);
        auto sn = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|classical|server_nonce_prefix|v1"), 4);

        benchmark::DoNotOptimize(cw);
        benchmark::DoNotOptimize(sw);
        benchmark::DoNotOptimize(fk);
        benchmark::DoNotOptimize(cn);
        benchmark::DoNotOptimize(sn);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
    state.SetLabel("HKDF-SHA256 extract + 5x expand (32-byte IKM)");
}
BENCHMARK(BM_KeyDerivation_Classical)->Unit(benchmark::kMicrosecond);

static void BM_KeyDerivation_Hybrid(benchmark::State& state) {
    Hkdf hkdf(HkdfHash::Sha256);
    const Bytes ikm(32, std::byte{0xCD});
    const std::size_t key_len = 32;

    auto before = capture_resources();
    for (auto _ : state) {
        auto prk_r = hkdf.extract(ByteSpan{}, ByteSpan{ikm});
        const SecureBytes& prk = prk_r.value();

        auto cw = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|hybrid|client_write_key|v1"), key_len);
        auto sw = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|hybrid|server_write_key|v1"), key_len);
        auto fk = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|hybrid|finished_key|v1"),     32);
        auto cn = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|hybrid|client_nonce_prefix|v1"), 4);
        auto sn = hkdf.expand(prk.span(), bytes_from_sv("uav_pqc|hybrid|server_nonce_prefix|v1"), 4);

        benchmark::DoNotOptimize(cw);
        benchmark::DoNotOptimize(sw);
        benchmark::DoNotOptimize(fk);
        benchmark::DoNotOptimize(cn);
        benchmark::DoNotOptimize(sn);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
    state.SetLabel("HKDF-SHA256 extract + 5x expand (hybrid, 32-byte IKM)");
}
BENCHMARK(BM_KeyDerivation_Hybrid)->Unit(benchmark::kMicrosecond);

// ─────────────────────────────────────────────────────────────────────────────
// KEM primitives in isolation (for comparison against full handshake overhead)
// ─────────────────────────────────────────────────────────────────────────────

static void BM_KemOnly_X25519_EncapDecap(benchmark::State& state) {
    X25519Kem kem;
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
    state.SetLabel("X25519 encap+decap");
}
BENCHMARK(BM_KemOnly_X25519_EncapDecap)->Unit(benchmark::kMicrosecond);

static void BM_KemOnly_MlKem768_EncapDecap(benchmark::State& state) {
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
    state.SetLabel("ML-KEM-768 encap+decap");
}
BENCHMARK(BM_KemOnly_MlKem768_EncapDecap)->Unit(benchmark::kMicrosecond);

static void BM_KemOnly_Hybrid_EncapDecap(benchmark::State& state) {
    HybridKem kem("uav_pqc|hybrid|kem|v1");
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
    state.SetLabel("ML-KEM-768||X25519 encap+decap");
}
BENCHMARK(BM_KemOnly_Hybrid_EncapDecap)->Unit(benchmark::kMicrosecond);

static void BM_KemOnly_MlKem1024_EncapDecap(benchmark::State& state) {
    MlKem kem(MlKem::Level::Kem1024);
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
    state.SetLabel("ML-KEM-1024 encap+decap");
}
BENCHMARK(BM_KemOnly_MlKem1024_EncapDecap)->Unit(benchmark::kMicrosecond);

// Main is provided by benchmark_main (linked via CMake)
