// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/app/ground_control_station.hpp"
#include "uav_pqc/app/uav.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/app/crypto_manager.hpp"
#include "uav_pqc/app/configuration_manager.hpp"
#include "uav_pqc/app/event_bus.hpp"
#include "uav_pqc/app/session_manager.hpp"
#include "uav_pqc/app/treekem_controller.hpp"
#include "uav_pqc/app/acpe_engine.hpp"
#include "uav_pqc/transport/fragment.hpp"
#include "uav_pqc/transport/channel_emulator.hpp"
#include "uav_pqc/sim/simulation_context.hpp"
#include "uav_pqc/protocol/message.hpp"

#include <iostream>
#include <fstream>
#include <queue>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <numeric>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace uav_pqc::sim {

// ─────────────────────────────────────────────────────────────────────────────
// Node-level metrics
// ─────────────────────────────────────────────────────────────────────────────
struct UavMetrics {
    NodeId      node_id{};
    std::string node_id_hex;
    uint64_t    start_time_ms            = 0;
    uint64_t    handshake_done_time_ms   = 0;
    uint64_t    enrollment_done_time_ms  = 0;

    double handshake_latency_ms     = 0.0;
    double registration_latency_ms  = 0.0;
    double authentication_latency_ms= 0.0;
    double treekem_rekey_ms         = 0.0;
    double treekem_update_ms        = 0.0;

    uint64_t packets_sent           = 0;
    uint64_t packets_received       = 0;
    uint64_t bytes_transferred      = 0;
    uint64_t loss_events            = 0;

    double cpu_execution_time_ms    = 0.0;
    double memory_usage_kb          = 0.0;

    // Channel-level statistics snapshot (filled by ChannelEmulator::stats())
    transport::ChannelStats channel_stats{};
};

struct SimNodeIdHash {
    std::size_t operator()(const NodeId& id) const noexcept {
        std::size_t h = 0;
        for (auto b : id) { h = (h * 31) + static_cast<std::size_t>(b); }
        return h;
    }
};

class SimNode;

// ─────────────────────────────────────────────────────────────────────────────
// Simulation Engine wrapping SimulationContext
// ─────────────────────────────────────────────────────────────────────────────
class SimulationEngine {
public:
    SimulationEngine(transport::ChannelEmulator emulator, uint64_t seed)
        : emulator_(std::move(emulator)) {
        SimulationConfig cfg;
        cfg.rng_seed = seed;
        cfg.auto_log_events = true;
        cfg.default_node_id = "SIM";
        context_ = std::make_unique<SimulationContext>(cfg);
    }

    void schedule(uint64_t time_ms, std::function<void()> callback, std::string tag = "") {
        (void)context_->schedule_event(time_ms, std::move(callback), std::move(tag));
    }

    void run() {
        context_->run_all();
    }

    void register_node(const NodeId& node_id, SimNode* node) {
        nodes_[node_id] = node;
    }

    std::string get_node_name(const NodeId& id) const {
        if (id == NodeId{}) return "GCS";
        int uav_idx = (static_cast<int>(id[0]) << 8) | static_cast<int>(id[1]);
        return "UAV-" + std::to_string(uav_idx);
    }

    void route_packet(const NodeId& src, const NodeId& dst, const Bytes& packet);

    [[nodiscard]] uint64_t now_ms() const noexcept { return context_->now_ms(); }

    UavMetrics& get_metrics(const NodeId& uav_id) { return uav_metrics_[uav_id]; }

    const std::unordered_map<NodeId, UavMetrics, SimNodeIdHash>& all_metrics() const noexcept {
        return uav_metrics_;
    }

    transport::ChannelEmulator& emulator() noexcept { return emulator_; }
    SimulationContext& context() noexcept { return *context_; }

private:
    std::unique_ptr<SimulationContext> context_;
    transport::ChannelEmulator emulator_;
    std::unordered_map<NodeId, SimNode*, SimNodeIdHash>          nodes_;
    std::unordered_map<NodeId, UavMetrics, SimNodeIdHash>        uav_metrics_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Simulated Node Wrapper
// ─────────────────────────────────────────────────────────────────────────────
class SimNode {
public:
    NodeId node_id;
    bool is_gcs = false;
    std::shared_ptr<app::EventBus>              event_bus;
    std::shared_ptr<app::ConfigurationManager>  config_mgr;
    std::shared_ptr<app::CryptoManager>         crypto_mgr;
    std::shared_ptr<app::INetworkManager>       network_mgr;
    std::shared_ptr<app::ISessionManager>       session_mgr;
    std::shared_ptr<app::IAcpeEngine>           acpe_engine;
    std::shared_ptr<app::ITreeKemController>    treekem_ctrl;

    std::unique_ptr<app::Uav>                   uav;
    std::unique_ptr<app::GroundControlStation>  gcs;

    SimNode(NodeId id, bool gcs_flag) : node_id(id), is_gcs(gcs_flag) {
        event_bus  = std::make_shared<app::EventBus>();
        config_mgr = std::make_shared<app::ConfigurationManager>();
        crypto_mgr = std::make_shared<app::CryptoManager>();
        session_mgr= std::make_shared<app::SessionManager>();
        acpe_engine= std::make_shared<app::AcpeEngine>();
    }

    void set_certificate(Bytes cert) { cert_ = std::move(cert); }

    VoidResult initialize(const std::string& config_str) {
        if (is_gcs) {
            treekem_ctrl = std::make_shared<app::TreeKemController>(
                protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256)
            );
            gcs = std::make_unique<app::GroundControlStation>(
                event_bus, config_mgr, crypto_mgr, network_mgr,
                session_mgr, acpe_engine, treekem_ctrl
            );
            if (!cert_.empty()) gcs->set_certificate(cert_);
            return gcs->initialize(config_str);
        } else {
            uav = std::make_unique<app::Uav>(
                event_bus, config_mgr, crypto_mgr, network_mgr,
                session_mgr, acpe_engine
            );
            if (!cert_.empty()) uav->set_certificate(cert_);
            return uav->initialize(config_str);
        }
    }

private:
    Bytes cert_;
};

// ─────────────────────────────────────────────────────────────────────────────
// SimulationEngine::route_packet — delegates to ChannelEmulator
// ─────────────────────────────────────────────────────────────────────────────
void SimulationEngine::route_packet(const NodeId& src, const NodeId& dst,
                                    const Bytes& packet) {
    // Track coarse send-side counters in UavMetrics (independent of channel fate)
    NodeId uav_key = (src == NodeId{}) ? dst : src;
    auto&  metrics = uav_metrics_[uav_key];
    metrics.packets_sent++;
    metrics.bytes_transferred += packet.size();

    uint64_t now = now_ms();
    std::string dst_name = get_node_name(dst);

    emulator_.route(src, dst, packet, now,
        [this, &metrics, dst_name](uint64_t delivery_ms,
                         const NodeId& s,
                         const NodeId& d,
                         const Bytes& pkt) {
            (void)s;
            schedule(delivery_ms, [this, d, pkt, delivery_ms, &metrics, dst_name]() {
                context_->set_node_context(dst_name);
                auto it = nodes_.find(d);
                if (it != nodes_.end()) {
                    it->second->network_mgr->handle_incoming_packet(pkt, delivery_ms);
                    metrics.packets_received++;
                }
            }, "PacketDelivery");
        }
    );

    // Sync drop count from emulator stats into UavMetrics
    const auto& ch = emulator_.stats();
    metrics.loss_events = ch.packets_dropped + ch.packets_overflow;
}

crypto::DsaKeyPair copy_keypair(const crypto::DsaKeyPair& kp) {
    crypto::DsaKeyPair result;
    result.public_key.data = kp.public_key.data;
    Bytes tmp(kp.private_key.span().begin(), kp.private_key.span().end());
    result.private_key.data = SecureBytes(std::move(tmp));
    return result;
}

} // namespace uav_pqc::sim

// ─────────────────────────────────────────────────────────────────────────────
// CLI helpers
// ─────────────────────────────────────────────────────────────────────────────
static void print_usage(const char* prog) {
    std::cout
        << "Usage: " << prog << " [OPTIONS]\n"
        << "\n"
        << "Options:\n"
        << "  --uavs <N>              Number of UAVs to simulate (1–1000, default: 10)\n"
        << "  --profile <name>        Channel profile: ideal_lan | wifi | 5g | satellite | custom\n"
        << "                          (default: wifi)\n"
        << "  --channel-config <path> Path to a JSON file containing a 'profiles' array\n"
        << "                          (overrides built-in profile values)\n"
        << "  --seed <N>              RNG seed for reproducible runs (default: 42)\n"
        << "  --trace                 Enable per-packet trace in results JSON\n"
        << "  --timeline <path>       Enable timeline logging and write to path (JSON) and path.txt (ASCII)\n"
        << "  --help                  Show this help and exit\n"
        << "\n"
        << "Built-in profiles:\n"
        << "  ideal_lan   — 0.1 ms delay, 1 Gbps, zero loss\n"
        << "  wifi        — 2 ms delay, 54 Mbps, 1% loss, 3 ms jitter\n"
        << "  5g          — 5 ms delay, 100 Mbps, 0.1% loss, 1 ms jitter\n"
        << "  satellite   — 600 ms delay, 10 Mbps, 0.5% loss, 50 ms jitter\n"
        << "  custom      — 15 ms delay, 54 Mbps, 2% loss, 2 ms jitter\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    int         num_uavs      = 10;
    std::string profile_name  = "wifi";
    std::string channel_config_path;
    uint64_t    rng_seed      = 42;
    bool        enable_trace  = false;
    std::string timeline_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--uavs" && i + 1 < argc) {
            num_uavs = std::stoi(argv[++i]);
        } else if (arg == "--profile" && i + 1 < argc) {
            profile_name = argv[++i];
        } else if (arg == "--channel-config" && i + 1 < argc) {
            channel_config_path = argv[++i];
        } else if (arg == "--seed" && i + 1 < argc) {
            rng_seed = std::stoull(argv[++i]);
        } else if (arg == "--trace") {
            enable_trace = true;
        } else if (arg == "--timeline" && i + 1 < argc) {
            timeline_path = argv[++i];
        }
        // Legacy compatibility — silent ignore of old --loss / --latency flags
        else if ((arg == "--loss" || arg == "--latency") && i + 1 < argc) {
            ++i; // consume value, no-op
        }
    }

    if (num_uavs < 1 || num_uavs > 1000) {
        std::cerr << "Invalid number of UAVs (1-1000 required): " << num_uavs << '\n';
        return 1;
    }

    // ── Load channel profile ──────────────────────────────────────────────
    uav_pqc::transport::ChannelProfile profile;
    try {
        if (!channel_config_path.empty()) {
            profile = uav_pqc::transport::ChannelProfile::load(profile_name, channel_config_path);
        } else {
            profile = uav_pqc::transport::ChannelProfile::builtin(profile_name);
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error loading channel profile '" << profile_name << "': "
                  << ex.what() << '\n';
        return 1;
    }

    if (enable_trace) {
        profile.params.enable_trace = true;
    }

    // ── Print banner ──────────────────────────────────────────────────────
    std::cout << "====================================================\n"
              << "Starting Standalone Protocol Simulation Engine\n"
              << "  UAV Swarm Size   : " << num_uavs << '\n'
              << "  Channel Profile  : " << profile.name << '\n'
              << "  Description      : " << profile.description << '\n'
              << "  Prop Delay       : " << profile.params.propagation_delay_ms << " ms\n"
              << "  Bandwidth        : " << (profile.params.bandwidth_bps / 1e6) << " Mbps\n"
              << "  Loss (good state): " << (profile.params.loss_good * 100.0) << " %\n"
              << "  Jitter (σ)       : " << profile.params.jitter_stddev_ms << " ms\n"
              << "  RNG Seed         : " << rng_seed << '\n'
              << "====================================================\n";

    // ── Initialize CA ─────────────────────────────────────────────────────
    uav_pqc::app::CryptoManager ca_crypto;
    uav_pqc::NodeId ca_id{std::byte{0xCA}};
    auto ca_key_r = ca_crypto.generate_dsa_keypair();
    if (!ca_key_r) {
        std::cerr << "CA keygen failed: " << ca_key_r.error().message << '\n';
        return 1;
    }
    uav_pqc::app::CertificateAuthority ca(ca_id, std::move(ca_key_r.value()));
    auto root_cert_r = ca.generate_root_certificate("Sim_CA", 31536000000ULL, 1000);
    if (!root_cert_r) {
        std::cerr << "CA root certificate failed: " << root_cert_r.error().message << '\n';
        return 1;
    }

    // ── Build simulation engine with emulator ─────────────────────────────
    uav_pqc::transport::ChannelEmulator emulator(profile.params, rng_seed);
    uav_pqc::sim::SimulationEngine sim(std::move(emulator), rng_seed);

    // ── GCS credentials ───────────────────────────────────────────────────
    uav_pqc::NodeId gcs_id{};
    uav_pqc::app::CryptoManager gcs_crypto_init;
    auto gcs_kp = gcs_crypto_init.generate_dsa_keypair().value();
    auto gcs_pub = gcs_kp.public_key;
    auto gcs_cert = ca.issue_certificate(
        "GCS_Node", gcs_id, uav_pqc::crypto::DsaPublicKey{}, gcs_pub, 3600000, 1000
    ).value();
    auto gcs_cert_der = gcs_cert.to_der();

    const std::string gcs_conf = R"({
        "node_id": "0000000000000000000000000000000000000000000000000000000000000000",
        "offered_modes": ["hybrid"]
    })";

    auto shared_treekem_ctrl = std::make_shared<uav_pqc::app::TreeKemController>(
        uav_pqc::protocol::CipherSuite::make_hybrid(uav_pqc::protocol::AeadAlgorithm::AesGcm256)
    );

    std::shared_ptr<uav_pqc::sim::SimNode> gcs_node;
    uav_pqc::NodeId active_uav_id{};
    uav_pqc::crypto::KemPublicKey active_uav_kem_pub;

    auto gcs_tx_fn = [&sim, &active_uav_id](const uav_pqc::Bytes& pkt) -> uav_pqc::VoidResult {
        sim.route_packet(uav_pqc::NodeId{}, active_uav_id, pkt);
        return uav_pqc::ok();
    };

    struct SwarmMemberContext {
        uav_pqc::NodeId                             node_id;
        uav_pqc::crypto::KemPublicKey               leaf_key;
        uav_pqc::crypto::KemPrivateKey              leaf_priv_key;
        std::shared_ptr<uav_pqc::app::ITreeKemController> treekem_ctrl;
    };
    std::vector<SwarmMemberContext> enrolled_uavs;
    std::vector<std::shared_ptr<uav_pqc::sim::SimNode>> uav_nodes;

    // ── Per-UAV simulation segments ───────────────────────────────────────
    for (int i = 1; i <= num_uavs; ++i) {
        uav_pqc::NodeId uav_id{};
        uav_id[0] = static_cast<std::byte>((i >> 8) & 0xFF);
        uav_id[1] = static_cast<std::byte>(i & 0xFF);

        std::stringstream ss;
        for (auto b : uav_id) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        std::string uav_id_hex = ss.str();

        auto uav_node = std::make_shared<uav_pqc::sim::SimNode>(uav_id, false);
        uav_nodes.push_back(uav_node);

        auto uav_tx_fn = [&sim, uav_id](const uav_pqc::Bytes& pkt) -> uav_pqc::VoidResult {
            sim.route_packet(uav_id, uav_pqc::NodeId{}, pkt);
            return uav_pqc::ok();
        };
        uav_node->network_mgr = std::make_shared<uav_pqc::app::NetworkManager>(uav_tx_fn, 500);

        auto uav_kp  = uav_node->crypto_mgr->generate_dsa_keypair().value();
        auto uav_pub = uav_kp.public_key;
        uav_node->crypto_mgr->set_static_dsa_keypair(std::move(uav_kp));

        auto uav_cert = ca.issue_certificate(
            "UAV_Node_" + std::to_string(i), uav_id,
            uav_pqc::crypto::DsaPublicKey{}, uav_pub, 3600000, 1000
        ).value();
        uav_node->set_certificate(uav_cert.to_der());

        std::string uav_conf = R"({"node_id": ")" + uav_id_hex + R"(","offered_modes": ["hybrid"]})";
        uav_node->initialize(uav_conf);
        sim.register_node(uav_id, uav_node.get());

        uav_pqc::crypto::MlKem mlkem(uav_pqc::crypto::MlKem::Level::Kem768);
        auto uav_kem_kp   = mlkem.generate_keypair().value();
        auto uav_kem_pub  = std::move(uav_kem_kp.public_key);
        auto uav_kem_priv = std::move(uav_kem_kp.private_key);

        auto& metrics         = sim.get_metrics(uav_id);
        metrics.node_id       = uav_id;
        metrics.node_id_hex   = uav_id_hex;
        metrics.memory_usage_kb = 12.0 + (enrolled_uavs.size() * 2.37);

        uint64_t uav_start_time = static_cast<uint64_t>(i - 1) * 5000ULL;
        uint64_t uav_stop_time  = uav_start_time + 4800ULL;

        sim.schedule(uav_start_time,
            [&sim, &metrics, gcs_id, &gcs_kp, gcs_cert_der, gcs_conf, gcs_tx_fn,
             shared_treekem_ctrl, &gcs_node, uav_node, uav_id, uav_kem_pub,
             &enrolled_uavs, uav_stop_time, &active_uav_id, &active_uav_kem_pub, i]()
        {
            sim.context().set_node_context("GCS");
            gcs_node = std::make_shared<uav_pqc::sim::SimNode>(gcs_id, true);
            gcs_node->treekem_ctrl = shared_treekem_ctrl;
            gcs_node->network_mgr  = std::make_shared<uav_pqc::app::NetworkManager>(gcs_tx_fn, 500);
            gcs_node->crypto_mgr->set_static_dsa_keypair(uav_pqc::sim::copy_keypair(gcs_kp));
            gcs_node->set_certificate(gcs_cert_der);
            gcs_node->initialize(gcs_conf);
            sim.register_node(gcs_id, gcs_node.get());

            active_uav_id      = uav_id;
            active_uav_kem_pub = uav_kem_pub;

            gcs_node->event_bus->subscribe<std::string>(
                [&metrics, &sim, gcs_node, uav_id, uav_kem_pub, &enrolled_uavs, i]
                (const std::string& ev) {
                    if (ev == "Handshake Complete with UAV") {
                        sim.context().set_node_context("GCS");
                        metrics.handshake_done_time_ms  = sim.now_ms();
                        metrics.handshake_latency_ms    = static_cast<double>(
                            metrics.handshake_done_time_ms - metrics.start_time_ms);
                        metrics.registration_latency_ms = metrics.handshake_latency_ms;

                        // Arm a TreeKEM rekey/enrollment timeout (30 seconds)
                        auto tk_timeout = std::make_shared<uav_pqc::sim::TimerHandle>();
                        *tk_timeout = sim.context().timers().treekem([uav_id, i]() {
                            std::cout << "[GCS] TreeKEM Enrollment TIMEOUT for UAV-" << i 
                                      << " (" << uav_pqc::to_hex(uav_id) << ")\n";
                        }, 30000);

                        auto rekey_start = std::chrono::high_resolution_clock::now();
                        auto rekey_r     = gcs_node->gcs->enroll_uav(uav_id, uav_kem_pub);
                        auto rekey_end   = std::chrono::high_resolution_clock::now();

                        metrics.treekem_rekey_ms =
                            std::chrono::duration<double, std::milli>(rekey_end - rekey_start).count();
                        metrics.enrollment_done_time_ms = sim.now_ms();
                        metrics.registration_latency_ms +=
                            static_cast<double>(metrics.enrollment_done_time_ms -
                                                metrics.handshake_done_time_ms);
                        metrics.cpu_execution_time_ms += metrics.treekem_rekey_ms;

                        if (rekey_r) {
                            // Cancel TreeKEM timer since rekey was successful
                            tk_timeout->cancel();

                            auto update = rekey_r.value();
                            for (const auto& member : enrolled_uavs) {
                                if (member.node_id == uav_id) continue;
                                auto update_start = std::chrono::high_resolution_clock::now();
                                auto update_r = member.treekem_ctrl->process_group_update(
                                    update, member.node_id, member.leaf_priv_key);
                                (void)update_r;
                                auto update_end = std::chrono::high_resolution_clock::now();
                                metrics.treekem_update_ms +=
                                    std::chrono::duration<double, std::milli>(
                                        update_end - update_start).count();
                            }
                            metrics.cpu_execution_time_ms += metrics.treekem_update_ms;
                        }
                    }
                }
            );

            // Arm periodic heartbeat timers to tick the GCS and UAV network managers.
            // When stop_time is reached, they cancel automatically.
            auto gcs_hb = std::make_shared<uav_pqc::sim::TimerHandle>();
            *gcs_hb = sim.context().timers().heartbeat([gcs_node, &sim, uav_stop_time, gcs_hb]() {
                sim.context().set_node_context("GCS");
                if (sim.now_ms() >= uav_stop_time) {
                    gcs_hb->cancel();
                    return;
                }
                gcs_node->network_mgr->tick(sim.now_ms());
            }, 100);

            auto uav_hb = std::make_shared<uav_pqc::sim::TimerHandle>();
            *uav_hb = sim.context().timers().heartbeat([uav_node, &sim, uav_stop_time, uav_hb, i]() {
                sim.context().set_node_context("UAV-" + std::to_string(i));
                if (sim.now_ms() >= uav_stop_time) {
                    uav_hb->cancel();
                    return;
                }
                uav_node->network_mgr->tick(sim.now_ms());
            }, 100);
        }, "RecreateGcs"
        );

        sim.schedule(uav_start_time + 50,
            [&metrics, &sim, uav_node, uav_id, i]() {
                sim.context().set_node_context("UAV-" + std::to_string(i));
                metrics.start_time_ms = sim.now_ms();

                // Arm handshake timeout timer (10 seconds)
                auto hs_timeout = std::make_shared<uav_pqc::sim::TimerHandle>();
                *hs_timeout = sim.context().timers().handshake([uav_id, i]() {
                    std::cout << "[UAV-" << i << "] Handshake TIMEOUT expired! (" << uav_pqc::to_hex(uav_id) << ")\n";
                }, 10000);

                // Arm simulated session lifetime timer (4 seconds)
                auto sess_timeout = std::make_shared<uav_pqc::sim::TimerHandle>();

                uav_node->event_bus->subscribe<std::string>(
                    [hs_timeout, sess_timeout, uav_id, i, &sim](const std::string& ev) {
                        if (ev == "Handshake Complete") {
                            sim.context().set_node_context("UAV-" + std::to_string(i));
                            if (hs_timeout->active()) {
                                hs_timeout->cancel();
                                std::cout << "[UAV-" << i << "] Handshake completed. Handshake timer cancelled.\n";
                            }
                            // Start session timer when handshake completes.
                            // Set session to expire after 4 seconds (4000 ms).
                            *sess_timeout = sim.context().timers().session([uav_id, i]() {
                                std::cout << "[UAV-" << i << "] Secure session EXPIRED! (" << uav_pqc::to_hex(uav_id) << ")\n";
                            }, 4000);
                        }
                    }
                );

                auto cpu_start = std::chrono::high_resolution_clock::now();
                uav_node->uav->start_handshake(sim.now_ms());
                auto cpu_end = std::chrono::high_resolution_clock::now();
                metrics.cpu_execution_time_ms +=
                    std::chrono::duration<double, std::milli>(cpu_end - cpu_start).count();
            }, "StartHandshake"
        );

        auto uav_treekem_ctrl = std::make_shared<uav_pqc::app::TreeKemController>(
            uav_pqc::protocol::CipherSuite::make_hybrid(uav_pqc::protocol::AeadAlgorithm::AesGcm256)
        );
        SwarmMemberContext ctx;
        ctx.node_id       = uav_id;
        ctx.leaf_key      = std::move(uav_kem_pub);
        ctx.leaf_priv_key = std::move(uav_kem_priv);
        ctx.treekem_ctrl  = uav_treekem_ctrl;
        enrolled_uavs.push_back(std::move(ctx));
    }

    // ── Run the discrete-event engine ─────────────────────────────────────
    sim.run();

    // Finalize channel stats
    double sim_duration_ms = static_cast<double>(num_uavs) * 5000.0;
    uint64_t sim_duration_ms_u64 = static_cast<uint64_t>(sim_duration_ms);
    sim.emulator().finalize(sim_duration_ms);

    // Copy final channel stats into every UAV metrics block
    for (auto& [id, m] : sim.all_metrics()) {
        const_cast<uav_pqc::sim::UavMetrics&>(m).channel_stats = sim.emulator().stats();
    }

    // ── Aggregate results ─────────────────────────────────────────────────
    std::vector<double> handshake_latencies, registration_latencies,
                        rekey_latencies, update_latencies;
    uint64_t total_sent = 0, total_received = 0, total_bytes = 0, total_loss = 0;
    double   total_cpu  = 0.0, max_memory_kb = 0.0;

    for (const auto& [id, m] : sim.all_metrics()) {
        handshake_latencies.push_back(m.handshake_latency_ms);
        registration_latencies.push_back(m.registration_latency_ms);
        rekey_latencies.push_back(m.treekem_rekey_ms);
        update_latencies.push_back(m.treekem_update_ms);
        total_sent     += m.packets_sent;
        total_received += m.packets_received;
        total_bytes    += m.bytes_transferred;
        total_loss     += m.loss_events;
        total_cpu      += m.cpu_execution_time_ms;
        max_memory_kb   = std::max(max_memory_kb, m.memory_usage_kb);
    }

    auto mean = [](const std::vector<double>& v) {
        return v.empty() ? 0.0 : std::accumulate(v.begin(), v.end(), 0.0) / v.size();
    };

    double avg_handshake     = mean(handshake_latencies);
    double avg_registration  = mean(registration_latencies);
    double avg_rekey         = mean(rekey_latencies);
    double avg_update        = mean(update_latencies);

    const auto& ch = sim.emulator().stats();

    // ── Console summary ───────────────────────────────────────────────────
    std::cout << "====================================================\n"
              << "Simulation Completed Successfully\n"
              << "  Avg Handshake Latency    : " << avg_handshake << " ms (virtual)\n"
              << "  Avg Registration Latency : " << avg_registration << " ms (virtual)\n"
              << "  Avg TreeKEM Rekey Time   : " << (avg_rekey * 1000.0) << " us (CPU)\n"
              << "  Avg TreeKEM Update Time  : " << (avg_update * 1000.0) << " us (CPU)\n"
              << "----------------------------------------------------\n"
              << "  Channel Profile          : " << profile.name << '\n'
              << "  Packets Enqueued         : " << ch.packets_enqueued << '\n'
              << "  Packets Delivered        : " << ch.packets_delivered << '\n'
              << "  Packets Dropped (loss)   : " << ch.packets_dropped << '\n'
              << "  Packets Dropped (overflow): " << ch.packets_overflow << '\n'
              << "  Packets Duplicated       : " << ch.packets_duplicated << '\n'
              << "  Packets Reordered        : " << ch.packets_reordered << '\n'
              << "  Measured Loss Rate       : " << (ch.loss_rate * 100.0) << " %\n"
              << "  Avg Channel Delay        : " << ch.avg_delay_ms << " ms\n"
              << "  Measured Jitter (σ)      : " << ch.measured_jitter_ms << " ms\n"
              << "  Effective Throughput     : " << (ch.effective_throughput_bps / 1e6) << " Mbps\n"
              << "----------------------------------------------------\n"
              << "  Total Packets Transmitted: " << total_sent << '\n'
              << "  Total Loss Events        : " << total_loss << '\n'
              << "  Total Bytes Transferred  : " << total_bytes << " bytes\n"
              << "  Total Cryptographic CPU  : " << total_cpu << " ms\n"
              << "  Max Estimated Memory     : " << max_memory_kb << " KB\n"
              << "====================================================\n";

    // ── CSV export ────────────────────────────────────────────────────────
    const std::string csv_path = "standalone_results.csv";
    if (std::ofstream csv_file(csv_path); csv_file.is_open()) {
        csv_file << "UavId,HandshakeLatencyMs,RegistrationLatencyMs,RekeyLatencyMs,"
                    "TreeKemUpdateMs,PacketsSent,PacketsReceived,BytesTransferred,"
                    "LossEvents,CpuTimeMs,MemoryKb,"
                    "ChDelivered,ChDropped,ChOverflow,ChDuplicated,ChReordered,"
                    "ChAvgDelayMs,ChJitterMs,ChLossRate,ChThroughputMbps\n";
        for (const auto& [id, m] : sim.all_metrics()) {
            csv_file << m.node_id_hex << ','
                     << m.handshake_latency_ms << ','
                     << m.registration_latency_ms << ','
                     << m.treekem_rekey_ms << ','
                     << m.treekem_update_ms << ','
                     << m.packets_sent << ','
                     << m.packets_received << ','
                     << m.bytes_transferred << ','
                     << m.loss_events << ','
                     << m.cpu_execution_time_ms << ','
                     << m.memory_usage_kb << ','
                     << ch.packets_delivered << ','
                     << ch.packets_dropped << ','
                     << ch.packets_overflow << ','
                     << ch.packets_duplicated << ','
                     << ch.packets_reordered << ','
                     << ch.avg_delay_ms << ','
                     << ch.measured_jitter_ms << ','
                     << ch.loss_rate << ','
                     << (ch.effective_throughput_bps / 1e6) << '\n';
        }
        std::cout << "Wrote CSV results to: " << csv_path << '\n';
    } else {
        std::cerr << "Failed to write CSV results\n";
    }

    // ── JSON export ───────────────────────────────────────────────────────
    const std::string json_path = "standalone_results.json";
    if (std::ofstream json_file(json_path); json_file.is_open()) {

        json channel_summary = {
            {"profile_name",      profile.name},
            {"profile_params",    profile.params.to_json()},
            {"stats",             ch.to_json()},
        };

        json summary = {
            {"num_uavs",                       num_uavs},
            {"rng_seed",                       rng_seed},
            {"avg_handshake_latency_ms",       avg_handshake},
            {"avg_registration_latency_ms",    avg_registration},
            {"avg_treekem_rekey_ms",           avg_rekey},
            {"avg_treekem_update_ms",          avg_update},
            {"total_packets_sent",             total_sent},
            {"total_packets_received",         total_received},
            {"total_bytes_transferred",        total_bytes},
            {"total_loss_events",              total_loss},
            {"total_cryptographic_cpu_ms",     total_cpu},
            {"max_estimated_memory_kb",        max_memory_kb},
            {"channel",                        channel_summary},
        };

        json details = json::array();
        for (const auto& [id, m] : sim.all_metrics()) {
            details.push_back({
                {"uav_id",                  m.node_id_hex},
                {"handshake_latency_ms",    m.handshake_latency_ms},
                {"registration_latency_ms", m.registration_latency_ms},
                {"treekem_rekey_ms",        m.treekem_rekey_ms},
                {"treekem_update_ms",       m.treekem_update_ms},
                {"packets_sent",            m.packets_sent},
                {"packets_received",        m.packets_received},
                {"bytes_transferred",       m.bytes_transferred},
                {"loss_events",             m.loss_events},
                {"cpu_execution_time_ms",   m.cpu_execution_time_ms},
                {"memory_usage_kb",         m.memory_usage_kb},
            });
        }

        // Per-packet trace (only if --trace was specified)
        json trace_arr = json::array();
        if (enable_trace) {
            for (const auto& rec : sim.emulator().trace()) {
                trace_arr.push_back({
                    {"seq",             rec.seq},
                    {"enqueue_ms",      rec.enqueue_time_ms},
                    {"deliver_ms",      rec.deliver_time_ms},
                    {"size_bytes",      rec.size_bytes},
                    {"fate",            static_cast<int>(rec.fate)},
                    {"total_delay_ms",  rec.total_delay_ms},
                });
            }
        }

        json output = {
            {"summary", summary},
            {"details", details},
            {"trace",   trace_arr},
        };

        json_file << output.dump(4);
        std::cout << "Wrote JSON results to: " << json_path << '\n';
    } else {
        std::cerr << "Failed to write JSON results\n";
    }

    // ── Export timeline if requested ──────────────────────────────────────
    if (!timeline_path.empty()) {
        sim.context().finalize();
        // Export JSON timeline
        if (sim.context().timeline().write_json(timeline_path, sim_duration_ms_u64)) {
            std::cout << "Wrote JSON timeline to: " << timeline_path << '\n';
        } else {
            std::cerr << "Failed to write JSON timeline\n";
        }
        
        // Also write ASCII swimlane to stdout or a .txt file if path ends with .txt
        std::string ascii_path = timeline_path;
        if (ascii_path.size() > 5 && ascii_path.substr(ascii_path.size() - 5) == ".json") {
            ascii_path = ascii_path.substr(0, ascii_path.size() - 5) + ".txt";
        } else {
            ascii_path += ".txt";
        }
        if (sim.context().timeline().write_ascii(ascii_path, 100)) {
            std::cout << "Wrote ASCII timeline to: " << ascii_path << '\n';
        }
    }

    // ── Export diagnostics metrics ─────────────────────────────────────────
    {
        const std::string metrics_csv_path = "standalone_metrics.csv";
        if (std::ofstream f(metrics_csv_path); f.is_open()) {
            uav_pqc::diagnostics::MetricsCollector::get_instance().export_csv(f);
            std::cout << "Wrote diagnostics metrics (CSV) to: " << metrics_csv_path << '\n';
        }
        const std::string metrics_json_path = "standalone_metrics.json";
        if (std::ofstream f(metrics_json_path); f.is_open()) {
            uav_pqc::diagnostics::MetricsCollector::get_instance().export_json(f);
            std::cout << "Wrote diagnostics metrics (JSON) to: " << metrics_json_path << '\n';
        }
        const std::string metrics_prom_path = "standalone_metrics.prom";
        if (std::ofstream f(metrics_prom_path); f.is_open()) {
            uav_pqc::diagnostics::MetricsCollector::get_instance().export_prometheus(f);
            std::cout << "Wrote diagnostics metrics (Prometheus) to: " << metrics_prom_path << '\n';
        }
    }

    return 0;
}
