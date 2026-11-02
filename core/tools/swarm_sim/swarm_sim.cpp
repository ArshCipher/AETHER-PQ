// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/app/ground_control_station.hpp"
#include "uav_pqc/app/uav.hpp"
#include "uav_pqc/app/event_bus.hpp"
#include "uav_pqc/app/configuration_manager.hpp"
#include "uav_pqc/app/crypto_manager.hpp"
#include "uav_pqc/app/session_manager.hpp"
#include "uav_pqc/app/acpe_engine.hpp"
#include "uav_pqc/app/treekem_controller.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <thread>
#include <queue>
#include <condition_variable>
#include <future>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <numeric>
#include <functional>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace uav_pqc;

// ── Custom NodeId Hash ───────────────────────────────────────────────────────
struct SimNodeIdHash {
    std::size_t operator()(const NodeId& id) const noexcept {
        std::size_t hash = 0;
        for (auto b : id) {
            hash = (hash * 31) + static_cast<std::size_t>(b);
        }
        return hash;
    }
};

// ── Thread Pool Implementation ───────────────────────────────────────────────
class ThreadPool {
public:
    explicit ThreadPool(std::size_t threads) : stop_(false) {
        for (std::size_t i = 0; i < threads; ++i) {
            workers_.emplace_back([this]() {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex_);
                        this->condition_.wait(lock, [this]() {
                            return this->stop_ || !this->tasks_.empty();
                        });
                        if (this->stop_ && this->tasks_.empty()) {
                            return;
                        }
                        task = std::move(this->tasks_.front());
                        this->tasks_.pop();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    auto enqueue(F&& f) -> std::future<typename std::invoke_result<F>::type> {
        using return_type = typename std::invoke_result<F>::type;
        auto task = std::make_shared<std::packaged_task<return_type()>>(std::forward<F>(f));
        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_) {
                throw std::runtime_error("enqueue on stopped ThreadPool");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        condition_.notify_one();
        return res;
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        condition_.notify_all();
        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    bool stop_;
};

// ── Concurrent Routing Hub ───────────────────────────────────────────────────
struct Router {
    std::mutex mutex;
    std::unordered_map<NodeId, std::function<VoidResult(ByteSpan, const NodeId&)>, SimNodeIdHash> routes;

    void register_route(const NodeId& id, std::function<VoidResult(ByteSpan, const NodeId&)> handler) {
        std::lock_guard<std::mutex> lock(mutex);
        routes[id] = std::move(handler);
    }

    void remove_route(const NodeId& id) {
        std::lock_guard<std::mutex> lock(mutex);
        routes.erase(id);
    }

    VoidResult route(const NodeId& sender, const NodeId& dst, ByteSpan msg) {
        std::function<VoidResult(ByteSpan, const NodeId&)> handler;
        {
            std::lock_guard<std::mutex> lock(mutex);
            auto it = routes.find(dst);
            if (it != routes.end()) {
                handler = it->second;
            }
        }
        if (handler) {
            return handler(msg, sender);
        }
        return err(ErrorCode::SessionNotFound, "Route not found");
    }
};

// ── Mock Swarm Network Manager ────────────────────────────────────────────────
class SwarmNetworkManager : public app::INetworkManager {
public:
    SwarmNetworkManager(NodeId self_id, Router& router)
        : self_id_(self_id), router_(router) {}

    VoidResult send_message(ByteSpan message) override {
        return router_.route(self_id_, peer_id_, message);
    }

    VoidResult send_message_to(const NodeId& destination, ByteSpan message) override {
        return router_.route(self_id_, destination, message);
    }

    void set_message_handler(app::MessageReceivedFn handler) override {
        msg_cb_ = std::move(handler);
    }

    VoidResult handle_incoming_packet(ByteSpan packet, Timestamp, const NodeId& sender) override {
        if (msg_cb_) {
            msg_cb_(sender, Bytes(packet.begin(), packet.end()));
        }
        return ok();
    }

    void tick(Timestamp) override {}

    void set_peer_id(NodeId peer) { peer_id_ = peer; }

private:
    NodeId self_id_;
    NodeId peer_id_;
    Router& router_;
    app::MessageReceivedFn msg_cb_;
};

// ── Simulated UAV Agent ──────────────────────────────────────────────────────
struct UavAgent {
    NodeId id;
    std::string name;
    double battery = 100.0;
    double x = 0.0;
    double y = 0.0;
    double z = 100.0;
    std::string mission = "Idle";
    protocol::OperatingMode mode = protocol::OperatingMode::Hybrid;
    bool failed = false;
    bool cert_expired = false;

    std::shared_ptr<app::EventBus> event_bus;
    std::shared_ptr<app::ConfigurationManager> config_mgr;
    std::shared_ptr<app::CryptoManager> crypto_mgr;
    std::shared_ptr<SwarmNetworkManager> network_mgr;
    std::shared_ptr<app::SessionManager> session_mgr;
    std::shared_ptr<app::AcpeEngine> acpe_engine;
    std::unique_ptr<app::Uav> uav;

    UavAgent(NodeId uav_id, const std::string& n, Router& router)
        : id(uav_id), name(n) {
        event_bus = std::make_shared<app::EventBus>();
        config_mgr = std::make_shared<app::ConfigurationManager>();
        crypto_mgr = std::make_shared<app::CryptoManager>();
        network_mgr = std::make_shared<SwarmNetworkManager>(id, router);
        network_mgr->set_peer_id(NodeId{}); // peer is GCS (zero NodeId)
        session_mgr = std::make_shared<app::SessionManager>();
        acpe_engine = std::make_shared<app::AcpeEngine>();

        uav = std::make_unique<app::Uav>(
            event_bus, config_mgr, crypto_mgr, network_mgr, session_mgr, acpe_engine
        );
    }
};

// ── Benchmark Results Tracker ────────────────────────────────────────────────
struct ScaleBenchmarkResult {
    std::size_t num_uavs = 0;
    double wall_time_ms = 0.0;
    double cpu_time_ms = 0.0;
    double total_allocations = 0.0;
    double total_memory_bytes = 0.0;
    std::size_t packets_transmitted = 0;
    std::size_t bytes_transmitted = 0;
};

// ── Run simulation for a specific Swarm Scale ───────────────────────────────
ScaleBenchmarkResult run_scale_simulation(std::size_t scale, ThreadPool& pool, Router& router) {
    std::cout << "[SwarmSim] Initializing Swarm Scale: " << scale << " UAVs..." << std::endl;

    // Reset diagnostic metrics database for this scale
    diagnostics::MetricsCollector::get_instance().clear();

    // 1. Create GCS Node
    NodeId gcs_id{};
    auto gcs_event_bus = std::make_shared<app::EventBus>();
    auto gcs_config_mgr = std::make_shared<app::ConfigurationManager>();
    auto gcs_crypto_mgr = std::make_shared<app::CryptoManager>();
    auto gcs_network_mgr = std::make_shared<SwarmNetworkManager>(gcs_id, router);
    auto gcs_session_mgr = std::make_shared<app::SessionManager>();
    auto gcs_acpe_engine = std::make_shared<app::AcpeEngine>();
    auto gcs_treekem_ctrl = std::make_shared<app::TreeKemController>(
        protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256)
    );

    auto gcs = std::make_shared<app::GroundControlStation>(
        gcs_event_bus, gcs_config_mgr, gcs_crypto_mgr, gcs_network_mgr,
        gcs_session_mgr, gcs_acpe_engine, gcs_treekem_ctrl
    );

    std::string gcs_cfg_json = R"({
        "node_id": "0000000000000000000000000000000000000000000000000000000000000000",
        "offered_modes": ["hybrid", "classical"]
    })";
    (void)gcs->initialize(gcs_cfg_json);

    // Register GCS packet route handler
    router.register_route(gcs_id, [gcs](ByteSpan pkt, const NodeId& sender) {
        return gcs->handle_incoming_uav_packet(sender, pkt, 0);
    });

    // 2. Populate UAV Swarm
    std::vector<std::shared_ptr<UavAgent>> swarm;
    swarm.reserve(scale);

    for (std::size_t i = 1; i <= scale; ++i) {
        NodeId uav_id{};
        uav_id[0] = static_cast<std::byte>((i) & 0xFF);
        uav_id[1] = static_cast<std::byte>((i >> 8) & 0xFF);

        std::string name = "UAV-" + std::to_string(i);
        auto agent = std::make_shared<UavAgent>(uav_id, name, router);

        std::stringstream ss;
        ss << R"({
            "node_id": ")" << to_hex(uav_id) << R"(",
            "offered_modes": ["hybrid", "classical"]
        })";
        (void)agent->uav->initialize(ss.str());

        // Register route handler for this UAV
        router.register_route(uav_id, [agent](ByteSpan pkt, const NodeId&) {
            if (agent->failed) return ok(); // fail silently
            return agent->uav->receive_packet(pkt, 0);
        });

        swarm.push_back(std::move(agent));
    }

    // Capture start time
    auto wall_start = std::chrono::high_resolution_clock::now();
    std::clock_t cpu_start = std::clock();

    // 3. Run Protocol Operations Concurrently
    std::vector<std::future<void>> futures;

    // Concurrent Handshakes (Session establishment)
    for (auto& agent : swarm) {
        futures.push_back(pool.enqueue([agent]() {
            if (agent->cert_expired) {
                // Mock expired certificate injection
                agent->uav->set_certificate({std::byte{0xDE}, std::byte{0xAD}});
            }
            (void)agent->uav->start_handshake(0);
        }));
    }

    // Wait for all handshakes to submit/run
    for (auto& f : futures) {
        f.get();
    }
    futures.clear();

    // Concurrent Telemetry sending and Dynamic Events (Battery, Mobility, Joins, Leaves)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> battery_drain(1.0, 30.0);
    std::uniform_real_distribution<> mobility_move(-10.0, 10.0);

    for (std::size_t idx = 0; idx < swarm.size(); ++idx) {
        auto agent = swarm[idx];
        futures.push_back(pool.enqueue([agent, idx, gcs, &battery_drain, &mobility_move, &gen]() {
            // Apply Dynamic UAV parameters
            // Model Mission States
            if (idx % 4 == 0) agent->mission = "Surveillance";
            else if (idx % 4 == 1) agent->mission = "Mapping";
            else if (idx % 4 == 2) agent->mission = "Intercept";
            else agent->mission = "Transit";

            // Battery drain simulation
            agent->battery -= battery_drain(gen);
            agent->uav->set_battery_level(agent->battery, 0);

            // Mobility updates
            agent->x += mobility_move(gen);
            agent->y += mobility_move(gen);

            // Trigger dynamic failure for 2% of swarm
            if (idx % 50 == 0) {
                agent->failed = true;
            }

            // Execute dynamic leave (Evict failed nodes from GCS TreeKEM)
            if (agent->failed) {
                (void)gcs->revoke_uav(agent->id);
            } else {
                // Execute dynamic join (Enroll into GCS TreeKEM)
                auto kem_kp_r = agent->crypto_mgr->generate_kem_keypair();
                if (kem_kp_r) {
                    (void)gcs->enroll_uav(agent->id, kem_kp_r.value().public_key);
                }

                // Send Telemetry concurrently
                std::string telemetry = "Telemetry payload from " + agent->name + " coords: " + std::to_string(agent->x);
                (void)agent->uav->send_telemetry(bytes_from_sv(telemetry));
            }
        }));
    }

    // Wait for dynamic actions to complete
    for (auto& f : futures) {
        f.get();
    }

    // Clean routes
    for (const auto& agent : swarm) {
        router.remove_route(agent.get()->id);
    }
    router.remove_route(gcs_id);

    // Record elapsed time
    std::clock_t cpu_end = std::clock();
    auto wall_end = std::chrono::high_resolution_clock::now();

    double cpu_duration = 1000.0 * static_cast<double>(cpu_end - cpu_start) / CLOCKS_PER_SEC;
    double wall_duration = std::chrono::duration<double, std::milli>(wall_end - wall_start).count();

    // 4. Collect Diagnostics Metrics
    ScaleBenchmarkResult res;
    res.num_uavs = scale;
    res.wall_time_ms = wall_duration;
    res.cpu_time_ms = cpu_duration;

    auto samples = diagnostics::MetricsCollector::get_instance().get_samples();
    for (const auto& s : samples) {
        if (s.type == diagnostics::MetricType::AllocCount) {
            res.total_allocations += s.value;
        } else if (s.type == diagnostics::MetricType::MemoryBytes) {
            res.total_memory_bytes += s.value;
        } else if (s.type == diagnostics::MetricType::PacketsTransmitted) {
            res.packets_transmitted += static_cast<std::size_t>(s.value);
        } else if (s.type == diagnostics::MetricType::BytesTransmitted) {
            res.bytes_transmitted += static_cast<std::size_t>(s.value);
        }
    }

    std::cout << "[SwarmSim] Completed scale " << scale << " in " << wall_duration << " ms (Wall time)\n" << std::endl;
    return res;
}

// ── Main Entry ───────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "====================================================" << std::endl;
    std::cout << "Starting Post-Quantum Swarm Sim Benchmarking Engine" << std::endl;
    std::cout << "====================================================" << std::endl;

    std::vector<std::size_t> target_scales = {10, 50, 100, 250, 500, 1000};

    // Override scales if provided as arguments
    if (argc > 1) {
        target_scales.clear();
        for (int i = 1; i < argc; ++i) {
            target_scales.push_back(std::stoul(argv[i]));
        }
    }

    Router router;
    ThreadPool pool(std::thread::hardware_concurrency());

    std::vector<ScaleBenchmarkResult> results;
    results.reserve(target_scales.size());

    for (std::size_t scale : target_scales) {
        auto res = run_scale_simulation(scale, pool, router);
        results.push_back(res);
    }

    // ── Export Results ────────────────────────────────────────────────────
    std::string csv_path = "swarm_benchmark_results.csv";
    std::ofstream csv_file(csv_path);
    if (csv_file.is_open()) {
        csv_file << "SwarmScale,WallTimeMs,CpuTimeMs,HeapAllocations,MemoryAllocatedBytes,PacketsTransmitted,BytesTransmitted\n";
        for (const auto& r : results) {
            csv_file << r.num_uavs << ","
                     << std::fixed << std::setprecision(3) << r.wall_time_ms << ","
                     << r.cpu_time_ms << ","
                     << r.total_allocations << ","
                     << r.total_memory_bytes << ","
                     << r.packets_transmitted << ","
                     << r.bytes_transmitted << "\n";
        }
        std::cout << "Wrote benchmark metrics (CSV) to: " << csv_path << std::endl;
    }

    std::string json_path = "swarm_benchmark_results.json";
    std::ofstream json_file(json_path);
    if (json_file.is_open()) {
        json j_arr = json::array();
        for (const auto& r : results) {
            j_arr.push_back({
                {"scale", r.num_uavs},
                {"wall_time_ms", r.wall_time_ms},
                {"cpu_time_ms", r.cpu_time_ms},
                {"heap_allocations", r.total_allocations},
                {"memory_allocated_bytes", r.total_memory_bytes},
                {"packets_transmitted", r.packets_transmitted},
                {"bytes_transmitted", r.bytes_transmitted}
            });
        }
        json_file << j_arr.dump(4);
        std::cout << "Wrote benchmark metrics (JSON) to: " << json_path << std::endl;
    }

    std::cout << "\nPost-Quantum Swarm Benchmarks Completed Successfully!\n";
    return 0;
}
