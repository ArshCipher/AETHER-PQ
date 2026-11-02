// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#include <benchmark/benchmark.h>
#include "uav_pqc/protocol/registration.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include <memory>
#include "bench_resources.hpp"

using namespace uav_pqc;
using namespace uav_pqc::protocol;
using namespace uav_pqc::app;

static void BM_GcsRegistrationProcessing(benchmark::State& state) {
    // Setup GCS CA
    NodeId ca_id{};
    ca_id[0] = std::byte{0xCA};
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto ca_kp = mldsa.generate_keypair();
    
    auto ca = std::make_unique<CertificateAuthority>(ca_id, std::move(ca_kp.value()));
    (void)ca->generate_root_certificate("Root_CA", 31536000000ULL, 1000);

    RegistrationDatabase db;
    GcsRegistrar gcs(db, *ca);

    // Setup UAV Request message
    crypto::EcdsaP256 ecdsa;
    auto ecdsa_kp = ecdsa.generate_keypair();
    auto mldsa_kp = mldsa.generate_keypair();
    
    UavRegistrar uav;
    auto req_pkt_r = uav.initiate_registration("UAV_01", ecdsa_kp.value(), mldsa_kp.value(), 10000);
    Bytes req_pkt = req_pkt_r.value();

    Timestamp time_counter = 10000;

    auto before = capture_resources();
    for (auto _ : state) {
        state.PauseTiming();
        // Prune the database record and seen nonces to allow processing identical requests in the loop
        db.clear(); 
        time_counter += 10;
        
        // Regenerate request with updated timestamp/nonce to bypass database duplicate and replay checks
        auto req_pkt_new_r = uav.initiate_registration("UAV_01", ecdsa_kp.value(), mldsa_kp.value(), time_counter);
        Bytes req_pkt_new = req_pkt_new_r.value();
        
        state.ResumeTiming();
        
        auto res = gcs.process_registration_request(req_pkt_new, time_counter);
        benchmark::DoNotOptimize(res);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after,
                           static_cast<double>(sizeof(RegisterAck)));
}

BENCHMARK(BM_GcsRegistrationProcessing);
