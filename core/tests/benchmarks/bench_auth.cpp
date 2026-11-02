// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#include <benchmark/benchmark.h>
#include "uav_pqc/protocol/auth.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include <memory>
#include "bench_resources.hpp"

using namespace uav_pqc;
using namespace uav_pqc::protocol;
using namespace uav_pqc::app;

static void BM_GcsAuthResponderReq(benchmark::State& state) {
    // Setup CA
    NodeId ca_node_id{};
    ca_node_id[0] = std::byte{0xCA};
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto kp_r = mldsa.generate_keypair();
    auto ca = std::make_unique<CertificateAuthority>(ca_node_id, std::move(kp_r.value()));
    (void)ca->generate_root_certificate("Root_CA", 31536000000ULL, 1000);

    // Setup GCS
    auto gcs_mldsa_kp = mldsa.generate_keypair().value();
    crypto::EcdsaP256 ecdsa;
    auto gcs_ecdsa_kp = ecdsa.generate_keypair().value();
    NodeId gcs_node_id{};
    gcs_node_id[0] = std::byte{0x01};
    auto gcs_cert = ca->issue_certificate("GCS", gcs_node_id, gcs_ecdsa_kp.public_key, gcs_mldsa_kp.public_key, 360000, 1000).value();

    // Setup UAV
    auto uav_mldsa_kp = mldsa.generate_keypair().value();
    auto uav_ecdsa_kp = ecdsa.generate_keypair().value();
    NodeId uav_node_id{};
    uav_node_id[0] = std::byte{0x02};
    auto uav_cert = ca->issue_certificate("UAV_01", uav_node_id, uav_ecdsa_kp.public_key, uav_mldsa_kp.public_key, 360000, 1000).value();

    UavAuthInitiator uav(uav_cert, uav_mldsa_kp, *ca->get_ca_certificate());
    Timestamp time_counter = 10000;

    auto before = capture_resources();
    for (auto _ : state) {
        state.PauseTiming();
        GcsAuthResponder gcs(gcs_cert, gcs_mldsa_kp, *ca->get_ca_certificate());
        time_counter += 10;
        
        auto req_pkt_r = uav.initiate(time_counter);
        Bytes req_pkt = req_pkt_r.value();
        
        state.ResumeTiming();
        
        auto ch_pkt_r = gcs.handle_req(req_pkt, time_counter);
        benchmark::DoNotOptimize(ch_pkt_r);
    }
    auto after = capture_resources();
    emit_resource_counters(state, before, after);
}

BENCHMARK(BM_GcsAuthResponderReq);
