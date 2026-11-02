// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/app/uav.hpp"
#include "uav_pqc/app/crypto_manager.hpp"
#include "uav_pqc/transport/transport.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <iostream>
#include <memory>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "cli_config.hpp"

using namespace uav_pqc;

// Fetch UAV certificate from CA
// Fetch certificate from CA over TCP (avoids IP fragmentation of ~2000-byte ML-DSA pubkey over BATMAN).
Bytes fetch_certificate_from_ca(const std::string& name, const NodeId& node_id, const crypto::DsaPublicKey& pubkey, const std::string& ca_ip, uint16_t ca_port) {
    std::vector<uint8_t> req;
    req.push_back(0x01); // RegisterReq
    req.insert(req.end(), reinterpret_cast<const uint8_t*>(node_id.data()),
               reinterpret_cast<const uint8_t*>(node_id.data() + node_id.size()));
    req.push_back(static_cast<uint8_t>(name.size()));
    req.insert(req.end(), name.begin(), name.end());

    uint32_t pubkey_len = static_cast<uint32_t>(pubkey.data.size());
    uint8_t size_buf[4];
    std::memcpy(size_buf, &pubkey_len, 4);
    req.insert(req.end(), size_buf, size_buf + 4);
    req.insert(req.end(), reinterpret_cast<const uint8_t*>(pubkey.data.data()),
               reinterpret_cast<const uint8_t*>(pubkey.data.data() + pubkey.data.size()));

    for (int retry = 0; retry < 5; ++retry) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { std::this_thread::sleep_for(std::chrono::milliseconds(500)); continue; }

        timeval tv{ 10, 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        sockaddr_in ca_addr{};
        ca_addr.sin_family      = AF_INET;
        ca_addr.sin_port        = htons(ca_port);
        ca_addr.sin_addr.s_addr = inet_addr(ca_ip.c_str());

        if (connect(sock, reinterpret_cast<sockaddr*>(&ca_addr), sizeof(ca_addr)) < 0) {
            close(sock); std::this_thread::sleep_for(std::chrono::milliseconds(500)); continue;
        }

        ssize_t sent = 0;
        while (sent < static_cast<ssize_t>(req.size())) {
            ssize_t n = send(sock, req.data() + sent, req.size() - sent, 0);
            if (n <= 0) { close(sock); goto next_retry; }
            sent += n;
        }

        {
            std::vector<uint8_t> reply(65535);
            ssize_t total = 0;
            while (total < 2) {
                ssize_t n = recv(sock, reply.data() + total, reply.size() - total, 0);
                if (n <= 0) break;
                total += n;
            }
            close(sock);
            if (total > 1 && reply[0] == 0x02) {
                Bytes cert_bytes(total - 1);
                std::transform(reply.begin() + 1, reply.begin() + total, cert_bytes.begin(),
                               [](uint8_t b) { return static_cast<std::byte>(b); });
                return cert_bytes;
            }
        }
        next_retry:
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    throw std::runtime_error("Failed to fetch UAV certificate from CA!");
}


int main(int argc, char* argv[]) {
    auto cfg = uav_pqc::process_sim::parse_args(argc, argv);
    int uav_index = cfg.node_id;

    std::cout << "[UAV-" << uav_index << "] Starting UAV process..." << std::endl;

    // Generate unique NodeId based on index
    NodeId uav_id{};
    uav_id[0] = static_cast<std::byte>((uav_index >> 8) & 0xFF);
    uav_id[1] = static_cast<std::byte>(uav_index & 0xFF);

    std::stringstream ss;
    for (auto b : uav_id) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::string uav_id_hex = ss.str();

    auto event_bus = std::make_shared<app::EventBus>();
    auto config_mgr = std::make_shared<app::ConfigurationManager>();
    auto crypto_mgr = std::make_shared<app::CryptoManager>();
    auto session_mgr = std::make_shared<app::SessionManager>();
    auto acpe_engine = std::make_shared<app::AcpeEngine>();

    // Generate dynamic keypair
    auto uav_kp = crypto_mgr->generate_dsa_keypair().value();
    auto uav_pub = uav_kp.public_key;
    crypto_mgr->set_static_dsa_keypair(std::move(uav_kp));

    Bytes uav_cert;
    try {
        uav_cert = fetch_certificate_from_ca("UAV_Node_" + std::to_string(uav_index), uav_id, uav_pub, cfg.ca_ip, cfg.ca_port);
        std::cout << "[UAV-" << uav_index << "] Registered with CA." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[UAV-" << uav_index << "] CA Registration Error: " << e.what() << std::endl;
        return 1;
    }

    // Set up transport
    auto transport = std::make_shared<transport::LinuxSocketTransport>();
    
    // Add route back to GCS
    NodeId gcs_id{}; // all zeros
    transport->add_route(gcs_id, cfg.gcs_ip, cfg.gcs_port);

    uint16_t listen_port = cfg.local_port != 0 ? cfg.local_port : static_cast<uint16_t>(28002 + uav_index);
    if (!transport->connect(cfg.local_ip + ":" + std::to_string(listen_port)).has_value()) {
        std::cerr << "[UAV-" << uav_index << "] Error: Failed to bind socket to " << cfg.local_ip << ":" << listen_port << std::endl;
        return 1;
    }

    // Offset stream ID to avoid collision at GCS
    transport::StreamId start_stream_id = static_cast<transport::StreamId>(uav_index) * 10000;
    auto network_mgr = std::make_shared<app::NetworkManager>(transport, 500, start_stream_id);

    // Pre-generate KEM leaf keys for TreeKEM enrollment
    crypto::MlKem mlkem(crypto::MlKem::Level::Kem768);
    auto kem_kp = mlkem.generate_keypair().value();
    auto kem_pub = std::move(kem_kp.public_key);

    auto uav = std::make_unique<app::Uav>(
        event_bus, config_mgr, crypto_mgr, network_mgr, session_mgr, acpe_engine
    );
    uav->set_treekem_private_key(std::move(kem_kp.private_key));
    uav->set_certificate(uav_cert);

    const std::string conf = R"({
        "node_id": ")" + uav_id_hex + R"(",
        "offered_modes": [")" + cfg.op_mode + R"("]
    })";
    uav->initialize(conf);

    // Initialize local loopback UDP forwarder for decrypted MAVLink sniffable traffic
    int forward_fd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in forward_addr{};
    if (forward_fd >= 0) {
        forward_addr.sin_family = AF_INET;
        forward_addr.sin_port = htons(14550);
        forward_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        std::cout << "[UAV-" << uav_index << "] MAVLink sniffer loopback forwarder initialized for 127.0.0.1:14550" << std::endl;
    }

    event_bus->subscribe<app::DecryptedMavlinkStream>([&, forward_fd, forward_addr](const app::DecryptedMavlinkStream& ev) {
        if (forward_fd >= 0 && !ev.data.empty()) {
            sendto(forward_fd, ev.data.data(), ev.data.size(), 0,
                   reinterpret_cast<const sockaddr*>(&forward_addr), sizeof(forward_addr));
        }
    });

    std::atomic<bool> handshake_done{false};

    event_bus->subscribe<std::string>([&](const std::string& ev) {
        if (ev == "Handshake Complete") {
            std::cout << "[UAV-" << uav_index << "] Handshake COMPLETE. Requesting TreeKEM enrollment..." << std::endl;
            
            // Build mock enrollment payload over secure telemetry/message layer
            Bytes enroll_req;
            enroll_req.push_back(std::byte{0xEE});
            enroll_req.insert(enroll_req.end(), uav_id.begin(), uav_id.end());
            uint32_t key_len = static_cast<uint32_t>(kem_pub.data.size());
            uint8_t size_buf[4];
            std::memcpy(size_buf, &key_len, 4);
            std::transform(size_buf, size_buf + 4, std::back_inserter(enroll_req),
                           [](uint8_t b) { return static_cast<std::byte>(b); });
            enroll_req.insert(enroll_req.end(), kem_pub.data.begin(), kem_pub.data.end());

            (void)uav->send_telemetry(enroll_req);
            handshake_done = true;
        }
    });

    // Start handshake
    auto clock = platform::make_platform_clock();
    std::cout << "[UAV-" << uav_index << "] Starting ACPE and Post-Quantum hybrid handshake with GCS..." << std::endl;
    uav->start_handshake(clock->now_ms());

    // Start a thread to read commands from stdin on the UAV node
    std::thread cmd_thread([&, uav_index]() {
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.rfind("send_file:", 0) == 0) {
                std::string filepath = line.substr(10);
                std::cout << "[UAV-" << uav_index << "] Initiating secure file transfer for: " << filepath << std::endl;
                std::ifstream infile(filepath, std::ios::binary);
                if (!infile.good()) {
                    std::cout << "[UAV-" << uav_index << "] Error: Cannot open file " << filepath << std::endl;
                    continue;
                }
                // Read file in chunks
                std::vector<char> buffer(1024);
                int chunk_index = 0;
                std::streamsize last_bytes_read = 0;
                while (infile.read(buffer.data(), buffer.size()) || infile.gcount() > 0) {
                    std::streamsize bytes_read = infile.gcount();
                    last_bytes_read = bytes_read;
                    Bytes chunk(bytes_read);
                    std::memcpy(chunk.data(), buffer.data(), bytes_read);

                    // Add a simple file header to identify this as file data
                    // Format: [FILE_TRANSFER_MAGIC (2 bytes: 0xFA, 0xCE)] [chunk_index (4 bytes)] [data]
                    Bytes wrapped_chunk;
                    wrapped_chunk.push_back(std::byte{0xFA});
                    wrapped_chunk.push_back(std::byte{0xCE});
                    uint32_t c_idx = static_cast<uint32_t>(chunk_index);
                    uint8_t idx_buf[4];
                    std::memcpy(idx_buf, &c_idx, 4);
                    wrapped_chunk.insert(wrapped_chunk.end(), reinterpret_cast<const std::byte*>(idx_buf), reinterpret_cast<const std::byte*>(idx_buf) + 4);
                    wrapped_chunk.insert(wrapped_chunk.end(), chunk.begin(), chunk.end());

                    auto res = uav->send_telemetry(wrapped_chunk);
                    if (res) {
                        std::cout << "[UAV-" << uav_index << "] Transmitted secure chunk " << chunk_index 
                                  << " (" << bytes_read << " bytes)." << std::endl;
                    } else {
                        std::cout << "[UAV-" << uav_index << "] Failed to transmit chunk " << chunk_index << ": " << res.error().message << std::endl;
                    }
                    chunk_index++;
                    std::this_thread::sleep_for(std::chrono::milliseconds(20)); // Flow control rate limit
                }
                
                // Send an explicit empty EOF chunk only if the last chunk was exactly 1024 bytes
                if (last_bytes_read == 1024) {
                    Bytes wrapped_eof;
                    wrapped_eof.push_back(std::byte{0xFA});
                    wrapped_eof.push_back(std::byte{0xCE});
                    uint32_t c_idx = static_cast<uint32_t>(chunk_index);
                    uint8_t idx_buf[4];
                    std::memcpy(idx_buf, &c_idx, 4);
                    wrapped_eof.insert(wrapped_eof.end(), reinterpret_cast<const std::byte*>(idx_buf), reinterpret_cast<const std::byte*>(idx_buf) + 4);
                    (void)uav->send_telemetry(wrapped_eof);
                }

                std::cout << "[UAV-" << uav_index << "] Secure file transfer COMPLETE." << std::endl;
            }
        }
    });
    cmd_thread.detach();

    // Instantiate Flight Controller simulator to generate valid MAVLink v2 telemetry
    app::mavlink::FlightControllerSimulator fc(static_cast<uint8_t>(uav_index));

    // Run event loops
    uint64_t last_telemetry_time = clock->now_ms();
    while (true) {
        auto now = clock->now_ms();
        network_mgr->tick(now);

        // Periodically stream telemetry if session established
        if (handshake_done && (now - last_telemetry_time > 3000)) {
            // Generate valid MAVLink v2 heartbeat frame
            auto hb_frame = fc.generate_heartbeat();
            auto hb_bytes = hb_frame.serialize();
            
            Bytes telemetry_payload(hb_bytes.size());
            std::transform(hb_bytes.begin(), hb_bytes.end(), telemetry_payload.begin(),
                           [](uint8_t b) { return static_cast<std::byte>(b); });

            (void)uav->send_telemetry(telemetry_payload);
            std::cout << "[UAV-" << uav_index << "] MAVLink Heartbeat telemetry sent (AES-GCM encrypted)." << std::endl;
            last_telemetry_time = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return 0;
}
