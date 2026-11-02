#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"
#include "uav_pqc/crypto/provider.hpp"
#include "uav_pqc/crypto/default_provider.hpp"
#include "uav_pqc/group/tree_kem.hpp"
#include "uav_pqc/app/uav.hpp"
#include "uav_pqc/app/ground_control_station.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

using namespace uav_pqc;

void run_ml_kem_benchmarks() {
    std::cout << "[Bench] Running ML-KEM-768 latency benchmarks..." << std::endl;
    crypto::MlKem mlkem(crypto::MlKem::Level::Kem768);
    auto kp = mlkem.generate_keypair().value();
    
    // Benchmark Encapsulation
    {
        diagnostics::ScopedProfiler prof(diagnostics::OpKind::MlKem);
        for (int i = 0; i < 50; ++i) {
            auto encap = mlkem.encapsulate(kp.public_key).value();
            (void)encap;
        }
    }
    
    // Benchmark Decapsulation
    auto encap = mlkem.encapsulate(kp.public_key).value();
    {
        diagnostics::ScopedProfiler prof(diagnostics::OpKind::MlKem);
        for (int i = 0; i < 50; ++i) {
            auto decap = mlkem.decapsulate(kp.private_key, encap.ciphertext).value();
            (void)decap;
        }
    }
}

void run_ml_dsa_benchmarks() {
    std::cout << "[Bench] Running ML-DSA-65 latency benchmarks..." << std::endl;
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto kp = mldsa.generate_keypair().value();
    Bytes msg(100, std::byte{0x01});
    
    // Benchmark Sign
    {
        diagnostics::ScopedProfiler prof(diagnostics::OpKind::MlDsa);
        for (int i = 0; i < 50; ++i) {
            auto sig = mldsa.sign(kp.private_key, msg).value();
            (void)sig;
        }
    }
    
    // Benchmark Verify
    auto sig = mldsa.sign(kp.private_key, msg).value();
    {
        diagnostics::ScopedProfiler prof(diagnostics::OpKind::MlDsa);
        for (int i = 0; i < 50; ++i) {
            auto ok = mldsa.verify(kp.public_key, msg, sig).value();
            (void)ok;
        }
    }
}

void run_aead_benchmarks() {
    std::cout << "[Bench] Running AES-GCM and ChaCha20 throughput benchmarks (1 MB blocks)..." << std::endl;
    auto crypto_provider = std::make_shared<crypto::DefaultCryptoProvider>();
    
    crypto::AeadKey key;
    key.data = SecureBytes(32);
    std::vector<std::byte> nonce(12, std::byte{0x01});
    Bytes plaintext(1024 * 1024, std::byte{0x41}); // 1 MB plaintext
    Bytes aad(16, std::byte{0x02});
    
    auto aes_gcm = crypto_provider->create_aes_gcm(crypto::AesKeyLen::Aes256);
    auto chacha = crypto_provider->create_chacha20_poly1305();
    
    // Benchmark AES-GCM 256
    {
        diagnostics::ScopedProfiler prof(diagnostics::OpKind::AesGcm);
        for (int i = 0; i < 10; ++i) {
            auto ct = aes_gcm->encrypt(key, nonce, plaintext, aad).value();
            (void)ct;
        }
    }
    
    // Benchmark ChaCha20-Poly1305
    {
        diagnostics::ScopedProfiler prof(diagnostics::OpKind::ChaCha20);
        for (int i = 0; i < 10; ++i) {
            auto ct = chacha->encrypt(key, nonce, plaintext, aad).value();
            (void)ct;
        }
    }
}

void run_treekem_benchmarks() {
    std::cout << "[Bench] Running TreeKEM rekey and update latency benchmarks..." << std::endl;
    std::shared_ptr<platform::IClock> clock = platform::make_platform_clock();
    auto crypto_provider = std::make_shared<crypto::DefaultCryptoProvider>();
    
    auto tree = group::make_tree_kem(protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256), clock, crypto_provider);
    
    // Add 10 mock members
    std::vector<group::SwarmMember> members;
    for (int i = 0; i < 10; ++i) {
        NodeId id{};
        id[0] = static_cast<std::byte>(i);
        crypto::MlKem mlkem(crypto::MlKem::Level::Kem768);
        auto kp = mlkem.generate_keypair().value();
        
        group::SwarmMember member;
        member.node_id = id;
        member.leaf_key = kp.public_key;
        members.push_back(member);
    }
    
    // Measure add member latency
    {
        diagnostics::ScopedProfiler prof(diagnostics::OpKind::TreeKem);
        for (int i = 0; i < 10; ++i) {
            auto update = tree->add_member(members[i], protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256)).value();
            (void)update;
        }
    }
}

void run_network_latency_benchmark(const std::string& target_ip, uint16_t target_port) {
    std::cout << "[Bench] Probing network latency / ping RTT to " << target_ip << ":" << target_port << "..." << std::endl;
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) return;
    
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(target_port);
    dest_addr.sin_addr.s_addr = inet_addr(target_ip.c_str());
    
    timeval tv{};
    tv.tv_sec = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Simple echo request / latency probe
    std::vector<uint8_t> ping(10, 0x99);
    auto start = std::chrono::high_resolution_clock::now();
    
    sendto(socket_fd, ping.data(), ping.size(), 0, reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr));
    
    std::vector<uint8_t> buffer(100);
    ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
    auto end = std::chrono::high_resolution_clock::now();
    close(socket_fd);
    
    if (received > 0) {
        double rtt_ms = std::chrono::duration<double, std::milli>(end - start).count();
        std::cout << "[Bench] Network latency RTT: " << rtt_ms << " ms" << std::endl;
        diagnostics::MetricsCollector::get_instance().record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::WallTimeMs, rtt_ms);
    } else {
        std::cout << "[Bench] Network target unreachable, local simulation assumed." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::string output_prefix = "hardware_benchmark_report";
    std::string target_ip = "127.0.0.1";
    uint16_t target_port = 28001;
    
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_prefix = argv[++i];
        } else if (std::strcmp(argv[i], "--target-ip") == 0 && i + 1 < argc) {
            target_ip = argv[++i];
        } else if (std::strcmp(argv[i], "--target-port") == 0 && i + 1 < argc) {
            target_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
    }
    
    std::cout << "==========================================" << std::endl;
    std::cout << "      UAV-PQC Hardware Benchmark Tool     " << std::endl;
    std::cout << "==========================================" << std::endl;
    
    run_ml_kem_benchmarks();
    run_ml_dsa_benchmarks();
    run_aead_benchmarks();
    run_treekem_benchmarks();
    run_network_latency_benchmark(target_ip, target_port);
    
    // Print CPU and memory estimates
    long page_size = sysconf(_SC_PAGESIZE);
    std::ifstream stat_file("/proc/self/stat");
    long rss_pages = 0;
    long vsize_bytes = 0;
    if (stat_file.good()) {
        std::string dummy;
        for (int i = 0; i < 22; ++i) stat_file >> dummy;
        stat_file >> vsize_bytes;
        stat_file >> rss_pages;
    }
    double rss_kb = (rss_pages * page_size) / 1024.0;
    double vsize_mb = vsize_bytes / (1024.0 * 1024.0);
    
    std::cout << "\n[Bench] Resource Utilization Summary:" << std::endl;
    std::cout << "  - Process Virtual Memory Size: " << vsize_mb << " MB" << std::endl;
    std::cout << "  - Process Resident Set Size (RSS): " << rss_kb << " KB" << std::endl;
    
    // Write reports
    std::ofstream csv_file(output_prefix + ".csv");
    diagnostics::MetricsCollector::get_instance().export_csv(csv_file);
    
    std::ofstream json_file(output_prefix + ".json");
    diagnostics::MetricsCollector::get_instance().export_json(json_file);
    
    std::cout << "\n[Bench] Completed successfully! Reports exported to " 
              << output_prefix << ".csv and " << output_prefix << ".json" << std::endl;
    
    return 0;
}
