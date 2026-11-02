// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/app/ground_control_station.hpp"
#include "uav_pqc/app/crypto_manager.hpp"
#include "uav_pqc/group/tree_kem.hpp"
#include "uav_pqc/transport/transport.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <iostream>
#include <memory>
#include <vector>
#include <chrono>
#include <thread>
#include <cstring>
#include <map>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "cli_config.hpp"

// Per-sender file transfer accumulator
struct FileTransferState {
    std::string filename;
    uint32_t    chunks_received = 0;
    uint64_t    bytes_received  = 0;
    std::ofstream outfile;
};

struct VideoStats {
    uint32_t last_seq = 0xFFFFFFFF;
    uint32_t received_count = 0;
    uint32_t lost_count = 0;
    uint32_t fps_count = 0;
    uint32_t bitrate_bytes = 0;
    uint64_t last_stats_time = 0;
    double current_fps = 0;
    double current_bitrate_kbps = 0;
    double current_loss = 0.0;
};

static std::string base64_encode(const unsigned char* data, size_t len) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        size_t remaining = len - i;
        if (remaining >= 3) {
            result.push_back(chars[(data[i] >> 2) & 0x3F]);
            result.push_back(chars[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)]);
            result.push_back(chars[((data[i+1] & 0x0F) << 2) | ((data[i+2] >> 6) & 0x03)]);
            result.push_back(chars[data[i+2] & 0x3F]);
        } else if (remaining == 2) {
            result.push_back(chars[(data[i] >> 2) & 0x3F]);
            result.push_back(chars[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)]);
            result.push_back(chars[(data[i+1] & 0x0F) << 2]);
            result.push_back('=');
        } else if (remaining == 1) {
            result.push_back(chars[(data[i] >> 2) & 0x3F]);
            result.push_back(chars[(data[i] & 0x03) << 4]);
            result.push_back('=');
            result.push_back('=');
        }
    }
    return result;
}

using namespace uav_pqc;

// Fetch GCS certificate from CA
// Fetch GCS certificate from CA over TCP.
// The registration request includes an ML-DSA public key (~1952 bytes), making
// the total packet ~2000 bytes which exceeds BATMAN-adv's effective MTU and causes
// silent IP-fragment loss over the mesh. TCP handles segmentation transparently.
Bytes fetch_certificate_from_ca(const std::string& name, const NodeId& node_id, const crypto::DsaPublicKey& pubkey, const std::string& ca_ip, uint16_t ca_port) {
    // Build request payload
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
        if (sock < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        timeval tv{ 10, 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        sockaddr_in ca_addr{};
        ca_addr.sin_family      = AF_INET;
        ca_addr.sin_port        = htons(ca_port);
        ca_addr.sin_addr.s_addr = inet_addr(ca_ip.c_str());

        if (connect(sock, reinterpret_cast<sockaddr*>(&ca_addr), sizeof(ca_addr)) < 0) {
            close(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
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
    throw std::runtime_error("Failed to fetch GCS certificate from CA!");
}


int main(int argc, char* argv[]) {
    auto cfg = uav_pqc::process_sim::parse_args(argc, argv);
    std::cout << "[GCS] Starting Ground Control Station process..." << std::endl;

    // Validate and create directories at GCS startup
    validate_and_create_directories(cfg, false, true, false);

    // Generate GCS NodeId
    NodeId gcs_id{}; // all zeros

    auto event_bus = std::make_shared<app::EventBus>();
    auto config_mgr = std::make_shared<app::ConfigurationManager>();
    auto crypto_mgr = std::make_shared<app::CryptoManager>();
    auto session_mgr = std::make_shared<app::SessionManager>();
    auto acpe_engine = std::make_shared<app::AcpeEngine>();
    
    // Select AEAD mode dynamically based on profile/mode if needed, fallback to default
    auto treekem_ctrl = std::make_shared<app::TreeKemController>(
        protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256)
    );

    treekem_ctrl->set_group_key_ready_fn([&](const group::GroupKey& gk) {
        session_mgr->set_group_key(gk.clone());
        std::cout << "[GCS] Callback: Instantiated and installed new TreeKEM GroupKey for epoch " << treekem_ctrl->get_epoch() << std::endl;
    });

    // Dynamic certificate registration
    auto gcs_kp = crypto_mgr->generate_dsa_keypair().value();
    auto gcs_pub = gcs_kp.public_key;
    crypto_mgr->set_static_dsa_keypair(std::move(gcs_kp));

    Bytes gcs_cert;
    try {
        gcs_cert = fetch_certificate_from_ca("GCS_Node", gcs_id, gcs_pub, cfg.ca_ip, cfg.ca_port);
        std::cout << "[GCS] Successfully registered and retrieved certificate from CA." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[GCS] CA Registration Error: " << e.what() << std::endl;
        return 1;
    }

    // Set up transport
    auto transport = std::make_shared<transport::LinuxSocketTransport>();
    
    // Register routing table dynamically
    bool loaded_custom_routes = false;
    if (!cfg.uav_routes_str.empty()) {
        std::stringstream ss(cfg.uav_routes_str);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (item.empty()) continue;
            std::stringstream item_ss(item);
            std::string id_str, ip, port_str;
            if (std::getline(item_ss, id_str, ':') &&
                std::getline(item_ss, ip, ':') &&
                std::getline(item_ss, port_str, ':')) {
                try {
                    int id = std::stoi(id_str);
                    uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                    NodeId uav_id{};
                    uav_id[0] = static_cast<std::byte>((id >> 8) & 0xFF);
                    uav_id[1] = static_cast<std::byte>(id & 0xFF);
                    transport->add_route(uav_id, ip, port);
                    loaded_custom_routes = true;
                } catch (...) {}
            }
        }
        if (loaded_custom_routes) {
            std::cout << "[GCS] Loaded custom UAV routes from command line/environment." << std::endl;
        }
    }

    if (!loaded_custom_routes && !cfg.config_path.empty()) {
        std::ifstream f(cfg.config_path);
        if (f.good()) {
            try {
                nlohmann::json j;
                f >> j;
                if (j.contains("uav_routes") && j["uav_routes"].is_array()) {
                    for (const auto& item : j["uav_routes"]) {
                        int id = item["id"].get<int>();
                        std::string ip = item["ip"].get<std::string>();
                        uint16_t port = item["port"].get<uint16_t>();
                        
                        NodeId uav_id{};
                        uav_id[0] = static_cast<std::byte>((id >> 8) & 0xFF);
                        uav_id[1] = static_cast<std::byte>(id & 0xFF);
                        transport->add_route(uav_id, ip, port);
                        loaded_custom_routes = true;
                    }
                    std::cout << "[GCS] Loaded custom UAV routes from configuration file." << std::endl;
                }
            } catch (...) {}
        }
    }

    // Populate the local loopback simulation routes only if no custom routes were loaded
    if (!loaded_custom_routes) {
        // Fallback to local loopback mapping loop
        for (int i = 1; i <= 1000; ++i) {
            NodeId uav_id{};
            uav_id[0] = static_cast<std::byte>((i >> 8) & 0xFF);
            uav_id[1] = static_cast<std::byte>(i & 0xFF);
            transport->add_route(uav_id, cfg.local_ip, static_cast<uint16_t>(28002 + i));
        }
    }

    uint16_t gcs_bind_port = cfg.local_port != 0 ? cfg.local_port : cfg.gcs_port;
    if (!transport->connect(cfg.local_ip + ":" + std::to_string(gcs_bind_port)).has_value()) {
        std::cerr << "[GCS] Error: Failed to bind socket to " << cfg.local_ip << ":" << gcs_bind_port << std::endl;
        return 1;
    }

    // Start GCS stream IDs at a high value so query commands never collide with
    // handshake stream IDs that the UAV already marked as "completed" (dedup cache)
    auto network_mgr = std::make_shared<app::NetworkManager>(transport, 500, 50000);

    auto gcs = std::make_unique<app::GroundControlStation>(
        event_bus, config_mgr, crypto_mgr, network_mgr, session_mgr, acpe_engine, treekem_ctrl
    );
    gcs->set_certificate(gcs_cert);

    const std::string conf = R"({
        "node_id": "0000000000000000000000000000000000000000000000000000000000000000",
        "offered_modes": [")" + cfg.op_mode + R"("]
    })";
    gcs->initialize(conf);

    // Initialize local loopback UDP forwarder for decrypted MAVLink sniffable traffic
    int forward_fd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in forward_addr{};
    if (forward_fd >= 0) {
        forward_addr.sin_family = AF_INET;
        forward_addr.sin_port = htons(14550);
        forward_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        std::cout << "[GCS] MAVLink sniffer loopback forwarder initialized for 127.0.0.1:14550" << std::endl;
    }

    event_bus->subscribe<app::DecryptedMavlinkStream>([&, forward_fd, forward_addr](const app::DecryptedMavlinkStream& ev) {
        if (forward_fd >= 0 && !ev.data.empty()) {
            sendto(forward_fd, ev.data.data(), ev.data.size(), 0,
                   reinterpret_cast<const sockaddr*>(&forward_addr), sizeof(forward_addr));
        }
    });

    std::map<NodeId, VideoStats> video_stats_map;

    event_bus->subscribe<app::DecryptedVideoFrame>([&](const app::DecryptedVideoFrame& ev) {
        if (ev.data.size() < 12) return;

        auto& stats = video_stats_map[ev.sender_id];
        uint64_t now_ms = platform::make_platform_clock()->wall_clock_ms();

        uint32_t ts = 0;
        uint32_t seq = 0;
        uint16_t width = 0;
        uint16_t height = 0;

        std::memcpy(&ts, &ev.data[0], 4);
        std::memcpy(&seq, &ev.data[4], 4);
        std::memcpy(&width, &ev.data[8], 2);
        std::memcpy(&height, &ev.data[10], 2);

        // Calculate packet/frame loss
        if (stats.last_seq != 0xFFFFFFFF) {
            if (seq > stats.last_seq + 1) {
                uint32_t lost = seq - (stats.last_seq + 1);
                stats.lost_count += lost;
            }
        }
        stats.last_seq = seq;
        stats.received_count++;

        stats.fps_count++;
        stats.bitrate_bytes += ev.data.size();

        if (stats.last_stats_time == 0) {
            stats.last_stats_time = now_ms;
        }
        if (now_ms - stats.last_stats_time >= 1000) {
            double dt = (now_ms - stats.last_stats_time) / 1000.0;
            stats.current_fps = stats.fps_count / dt;
            stats.current_bitrate_kbps = (stats.bitrate_bytes * 8.0) / 1024.0 / dt;

            uint32_t total = stats.received_count + stats.lost_count;
            if (total > 0) {
                stats.current_loss = (double)stats.lost_count / total;
            }

            stats.fps_count = 0;
            stats.bitrate_bytes = 0;
            stats.last_stats_time = now_ms;
        }

        uint32_t latency = 0;
        uint32_t now_32 = static_cast<uint32_t>(now_ms & 0xFFFFFFFF);
        if (now_32 >= ts) {
            latency = now_32 - ts;
        }

        const unsigned char* jpeg_ptr = reinterpret_cast<const unsigned char*>(ev.data.data() + 12);
        size_t jpeg_len = ev.data.size() - 12;

        std::string b64 = base64_encode(jpeg_ptr, jpeg_len);

        int uav_idx = static_cast<int>(ev.sender_id[1]);
        std::string id_str = "UAV-00" + std::to_string(uav_idx);

        std::cout << "[UI_EVENT] {\"event\": \"video_frame\", \"id\": \"" << id_str 
                  << "\", \"frame\": \"data:image/jpeg;base64," << b64 
                  << "\", \"timestamp\": " << ts 
                  << ", \"sequence\": " << seq 
                  << ", \"width\": " << width 
                  << ", \"height\": " << height 
                  << ", \"fps\": " << stats.current_fps
                  << ", \"bitrate\": " << stats.current_bitrate_kbps
                  << ", \"latency\": " << latency
                  << ", \"loss\": " << stats.current_loss << "}" << std::endl;
    });

    // Subscribe to GCS Handshake completions
    event_bus->subscribe<std::string>([&](const std::string& ev) {
        if (ev.rfind("Handshake Complete with UAV", 0) == 0) {
            std::cout << "[GCS] " << ev << " (Authentic session established)" << std::endl;
            // Parse UAV index
            size_t pos = ev.find("UAV-");
            if (pos != std::string::npos) {
                std::string uav_idx_str = ev.substr(pos + 4);
                int uav_idx = std::stoi(uav_idx_str);
                std::string id_str = "UAV-00" + std::to_string(uav_idx);
                std::cout << "[UI_EVENT] {\"event\": \"handshake\", \"id\": \"" << id_str << "\", \"status\": \"completed\", \"profile\": \"X25519+ML-KEM-1024\"}" << std::endl;
            }
        }
    });

    // Per-sender file transfer accumulator (keyed by sender_key string)
    std::map<std::string, FileTransferState> file_transfers;
    std::string last_requested_filename = "received_file.bin";
    std::mutex last_filename_mutex;

    // Handle TreeKEM enrollment triggers and telemetry sent over secure messaging
    event_bus->subscribe<Bytes>([&](const Bytes& msg) {
        if (msg.size() > 37 && msg[0] == std::byte{0xEE}) { // Mock Enrollment Message
            NodeId uav_id{};
            std::copy(msg.begin() + 1, msg.begin() + 33, uav_id.begin());

            uint32_t pubkey_len = 0;
            std::memcpy(&pubkey_len, &msg[33], 4);

            if (msg.size() >= 37 + pubkey_len) {
                crypto::KemPublicKey uav_kem_pub;
                uav_kem_pub.data.resize(pubkey_len);
                std::copy(msg.begin() + 37, msg.begin() + 37 + pubkey_len, uav_kem_pub.data.begin());

                // Derive UAV index
                int uav_idx = static_cast<int>(uav_id[1]);
                std::string id_str = "UAV-00" + std::to_string(uav_idx);
                std::cout << "[GCS] Received TreeKEM enrollment request from UAV. Processing group update..." << std::endl;
                std::cout << "[UI_EVENT] {\"event\": \"treekem_enroll\", \"id\": \"" << id_str << "\"}" << std::endl;
                
                auto rekey_r = gcs->enroll_uav(uav_id, uav_kem_pub);
                if (rekey_r) {
                    std::cout << "[GCS] TreeKEM Rekey SUCCESS. Broadcasting GroupKeyUpdate to all swarm nodes." << std::endl;
                    std::cout << "[UI_EVENT] {\"event\": \"treekem_rekey\", \"status\": \"success\", \"epoch\": " << treekem_ctrl->get_epoch() << "}" << std::endl;

                    // Serialize and broadcast GCS authoritative TreeKEM state to synchronize swarm membership
                    auto tree_ser_r = treekem_ctrl->serialize_tree();
                    if (tree_ser_r) {
                        auto tree_packet = protocol::wrap_packet(protocol::ProtocolID::TREEKEM, tree_ser_r.value(), 0);
                        network_mgr->send_message(tree_packet);
                        std::cout << "[GCS] Broadcasted serialized TreeKEM state to all nodes." << std::endl;
                    }

                    // Serialize and Broadcast GroupKeyUpdate
                    auto ser_r = group::serialize_group_key_update(rekey_r.value());
                    if (ser_r) {
                        // Small delay to let UDP stack flush the tree state packet first
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        auto packet = protocol::wrap_packet(protocol::ProtocolID::TREEKEM, ser_r.value(), 0);
                        auto transmit_res = network_mgr->send_message(packet);
                        if (!transmit_res) {
                            std::cerr << "[GCS] Error: Failed to broadcast GroupKeyUpdate: " << transmit_res.error().message << std::endl;
                        } else {
                            std::cout << "[GCS] Successfully broadcasted GroupKeyUpdate packet." << std::endl;
                        }
                    } else {
                        std::cerr << "[GCS] Error: Failed to serialize GroupKeyUpdate" << std::endl;
                    }
                }
            }
        } else {
            if (msg.size() >= 6 && msg[0] == std::byte{0xFA} && msg[1] == std::byte{0xCE}) { // File Transfer Magic
                uint32_t chunk_idx = 0;
                std::memcpy(&chunk_idx, &msg[2], 4);
                std::string sender_key = "default";

                // Determine output filename from the last requested filename
                if (file_transfers.find(sender_key) == file_transfers.end()) {
                    // New transfer starting
                    file_transfers[sender_key] = FileTransferState{};
                    std::string fname;
                    {
                        std::lock_guard<std::mutex> lock(last_filename_mutex);
                        fname = last_requested_filename;
                    }
                    file_transfers[sender_key].filename = fname;
                    std::string out_path = cfg.paths.download_dir + "/" + file_transfers[sender_key].filename;
                    file_transfers[sender_key].outfile.open(
                        out_path,
                        std::ios::binary | std::ios::trunc);
                }
                auto& xfer = file_transfers[sender_key];
                if (chunk_idx < xfer.chunks_received) {
                    std::cout << "[GCS] Duplicate chunk ignored: index=" << chunk_idx << std::endl;
                    return;
                }
                size_t data_start = 6;
                size_t data_len   = msg.size() - data_start;

                if (xfer.outfile.good() && data_len > 0) {
                    xfer.outfile.write(reinterpret_cast<const char*>(&msg[data_start]), data_len);
                    xfer.outfile.flush();
                }
                xfer.chunks_received++;
                xfer.bytes_received += data_len;

                std::cout << "[GCS] Secure file transfer chunk received: index=" << chunk_idx
                          << " size=" << data_len << " bytes (AES-GCM decryption verified)." << std::endl;
                std::cout << "[UI_EVENT] {\"event\": \"file_transfer_progress\", \"chunk\": " << chunk_idx
                          << ", \"bytes\": " << xfer.bytes_received << "}" << std::endl;

                // A short chunk (< 1024 bytes) signals end of file
                if (data_len < 1024) {
                    xfer.outfile.close();
                    std::cout << "[GCS] Secure file transfer COMPLETE. Saved to: " << xfer.filename << std::endl;
                    std::cout << "[UI_EVENT] {\"event\": \"file_transfer_complete\", \"filename\": \""
                              << xfer.filename << "\", \"bytes\": " << xfer.bytes_received << "}" << std::endl;
                    file_transfers.erase(sender_key);
                }
            } else if (msg.size() > 5 && msg[0] == std::byte{0xFB} && msg[1] == std::byte{0xCB}) { // Query Response Magic
                uint8_t qtype = static_cast<uint8_t>(msg[2]);
                int uav_idx = static_cast<int>(msg[4]);
                std::string res_str(reinterpret_cast<const char*>(&msg[5]), msg.size() - 5);
                std::string id_str = "UAV-00" + std::to_string(uav_idx);
                std::cout << "[GCS] Secure query response received from " << id_str << " for type=" << (int)qtype << std::endl;
                
                // Print UI event
                nlohmann::json j_ev;
                j_ev["event"] = "query_result";
                j_ev["id"] = id_str;
                j_ev["queryType"] = static_cast<int>(qtype);
                j_ev["result"] = res_str;
                std::cout << "[UI_EVENT] " << j_ev.dump() << std::endl;
            } else {
                // Reassembled telemetry print
                std::string payload(reinterpret_cast<const char*>(msg.data()), msg.size());
                std::cout << "[GCS] Reassembled telemetry payload: " << payload << std::endl;

                // Simple parser
                size_t uav_pos = payload.find("UAV-");
                size_t alt_pos = payload.find("Alt=");
                size_t volt_pos = payload.find("Volt=");
                size_t status_pos = payload.find("Status=");

                if (uav_pos != std::string::npos && alt_pos != std::string::npos &&
                    volt_pos != std::string::npos && status_pos != std::string::npos) {
                    
                    std::string uav_num_str = payload.substr(uav_pos + 4, alt_pos - (uav_pos + 4) - 1);
                    std::string uav_id = "UAV-00" + uav_num_str;
                    std::string alt = payload.substr(alt_pos + 4, volt_pos - (alt_pos + 4) - 1);
                    std::string volt = payload.substr(volt_pos + 5, status_pos - (volt_pos + 5) - 1);
                    std::string status = payload.substr(status_pos + 7);

                    // Print UI event
                    std::cout << "[UI_EVENT] {\"event\": \"telemetry\", \"id\": \"" << uav_id 
                              << "\", \"altitude\": " << alt.substr(0, alt.size() - 1) 
                              << ", \"voltage\": " << volt.substr(0, volt.size() - 1) 
                              << ", \"status\": \"" << status << "\"}" << std::endl;
                }
            }
        }
    });

    std::cout << "[GCS] GCS process is listening and active." << std::endl;

    // Start a thread to read commands from stdin
    std::thread cmd_thread([&]() {
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line == "rekey") {
                std::cout << "[GCS] Manual Rekey Triggered via Stdin Command." << std::endl;
                auto rekey_r = gcs->get_treekem_controller()->rotate_keys(group::RekeyReason::ManualRotation);
                if (rekey_r) {
                    std::cout << "[GCS] TreeKEM Manual Rekey SUCCESS. Broadcasting GroupKeyUpdate to all swarm nodes." << std::endl;
                    std::cout << "[UI_EVENT] {\"event\": \"treekem_rekey\", \"status\": \"success\", \"epoch\": " 
                              << treekem_ctrl->get_epoch() << "}" << std::endl;
                } else {
                    std::cout << "[GCS] TreeKEM Manual Rekey FAILED." << std::endl;
                }
            } else if (line.rfind("policy:", 0) == 0) {
                std::string mode_str = line.substr(7);
                std::cout << "[GCS] Policy Update Triggered: " << mode_str << std::endl;
                std::cout << "[UI_EVENT] {\"event\": \"policy\", \"mode\": \"" << mode_str << "\"}" << std::endl;

                policy::AcpeDecision dec{};
                if (mode_str == "L1-CLASSICAL") {
                    dec.mode = protocol::OperatingMode::Classical;
                } else if (mode_str == "L2-TRANSITION") {
                    dec.mode = protocol::OperatingMode::Transition;
                } else if (mode_str == "L3-HYBRID") {
                    dec.mode = protocol::OperatingMode::Hybrid;
                } else if (mode_str == "L4-PQ-ONLY" || mode_str == "PQOnly") {
                    dec.mode = protocol::OperatingMode::PqcOnly;
                } else {
                    dec.mode = protocol::OperatingMode::Hybrid;
                }
                dec.profile = policy::CryptographicProfile::Standard;
                gcs->broadcast_policy_update(dec);
            } else if (line.rfind("revoke:", 0) == 0) {
                std::string idx_str = line.substr(7);
                try {
                    int uav_idx = std::stoi(idx_str);
                    std::cout << "[GCS] Revoke UAV Command: " << uav_idx << std::endl;
                    NodeId uav_id{};
                    uav_id[0] = static_cast<std::byte>((uav_idx >> 8) & 0xFF);
                    uav_id[1] = static_cast<std::byte>(uav_idx & 0xFF);
                    auto revoke_r = gcs->revoke_uav(uav_id);
                    if (revoke_r) {
                        std::cout << "[GCS] TreeKEM Revocation Rekey SUCCESS." << std::endl;
                        std::cout << "[UI_EVENT] {\"event\": \"treekem_rekey\", \"status\": \"success\", \"epoch\": " 
                                  << treekem_ctrl->get_epoch() << "}" << std::endl;

                        // Serialize and broadcast GCS authoritative TreeKEM state to synchronize swarm membership
                        auto tree_ser_r = treekem_ctrl->serialize_tree();
                        if (tree_ser_r) {
                            auto tree_packet = protocol::wrap_packet(protocol::ProtocolID::TREEKEM, tree_ser_r.value(), 0);
                            network_mgr->send_message(tree_packet);
                            std::cout << "[GCS] Broadcasted serialized TreeKEM state to all nodes." << std::endl;
                        }

                        // Serialize and Broadcast GroupKeyUpdate
                        auto ser_r = group::serialize_group_key_update(revoke_r.value());
                        if (ser_r) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                            auto packet = protocol::wrap_packet(protocol::ProtocolID::TREEKEM, ser_r.value(), 0);
                            auto transmit_res = network_mgr->send_message(packet);
                            if (!transmit_res) {
                                std::cerr << "[GCS] Error: Failed to broadcast GroupKeyUpdate: " << transmit_res.error().message << std::endl;
                            } else {
                                std::cout << "[GCS] Successfully broadcasted GroupKeyUpdate packet." << std::endl;
                            }
                        }
                    } else {
                        std::cout << "[GCS] TreeKEM Revocation Rekey FAILED." << std::endl;
                    }
                } catch (...) {
                    std::cout << "[GCS] Revoke UAV Command Failed: invalid index" << std::endl;
                }
            } else if (line.rfind("broadcast_cmd:", 0) == 0) {
                std::string cmd_id_str = line.substr(14);
                try {
                    uint16_t command_id = static_cast<uint16_t>(std::stoi(cmd_id_str));
                    std::cout << "[GCS] Swarm Broadcast MAVLink Command Triggered: " << command_id << std::endl;
                    app::mavlink::CommandLong cmd{
                        .param1 = 1.0f,
                        .param2 = 2.0f,
                        .param3 = 3.0f,
                        .param4 = 4.0f,
                        .param5 = 5.0f,
                        .param6 = 6.0f,
                        .param7 = 7.0f,
                        .command = command_id,
                        .target_system = 0,
                        .target_component = 0,
                        .confirmation = 0
                    };
                    gcs->send_mavlink_command(NodeId{}, cmd);
                } catch (...) {
                    std::cout << "[GCS] Swarm Broadcast MAVLink Command Failed: invalid command ID" << std::endl;
                }
            } else if (line.rfind("query_uav:", 0) == 0) {
                std::string rest = line.substr(10);
                size_t p1 = rest.find(':');
                if (p1 != std::string::npos) {
                    std::string idx_str = rest.substr(0, p1);
                    std::string rest2 = rest.substr(p1 + 1);
                    size_t p2 = rest2.find(':');
                    if (p2 != std::string::npos) {
                        std::string qtype_str = rest2.substr(0, p2);
                        std::string path_or_key = rest2.substr(p2 + 1);

                        try {
                            int uav_idx = std::stoi(idx_str);
                            uint8_t qtype = static_cast<uint8_t>(std::stoi(qtype_str));

                            std::cout << "[GCS] Querying UAV " << uav_idx << " for type=" << (int)qtype 
                                      << " key=" << path_or_key << std::endl;

                            if (qtype == 6) {
                                size_t last_slash = path_or_key.find_last_of("/\\");
                                std::string fname = (last_slash != std::string::npos) ? path_or_key.substr(last_slash + 1) : path_or_key;
                                if (fname.empty()) {
                                    fname = "received_file.bin";
                                }
                                std::lock_guard<std::mutex> lock(last_filename_mutex);
                                last_requested_filename = fname;
                            }

                            NodeId uav_id{};
                            uav_id[0] = static_cast<std::byte>((uav_idx >> 8) & 0xFF);
                            uav_id[1] = static_cast<std::byte>(uav_idx & 0xFF);

                            // Build query request payload
                            Bytes req;
                            req.push_back(std::byte{0xFB});
                            req.push_back(std::byte{0xCA});
                            req.push_back(static_cast<std::byte>(qtype));
                            req.insert(req.end(), reinterpret_cast<const std::byte*>(path_or_key.data()), 
                                       reinterpret_cast<const std::byte*>(path_or_key.data()) + path_or_key.size());

                            auto active_sessions = gcs->get_active_uav_sessions();
                            auto it = active_sessions.find(uav_id);
                            if (it != active_sessions.end()) {
                                auto sess_r = gcs->get_session_manager()->get_session(it->second, uav_id, 0);
                                if (sess_r) {
                                    auto enc_r = sess_r.value()->encrypt(req, ByteSpan{});
                                    if (enc_r) {
                                        auto send_r = gcs->get_network_manager()->send_message_to(uav_id, protocol::wrap_packet(protocol::ProtocolID::COMMAND, enc_r.value(), 1, it->second));
                                        if (send_r) {
                                            std::cout << "[GCS] Query request transmitted securely." << std::endl;
                                        } else {
                                            std::cerr << "[GCS Error] Failed to send query request packet: " << send_r.error().message << std::endl;
                                        }
                                    }
                                }
                            } else {
                                std::cout << "[GCS] Error: UAV session not active." << std::endl;
                            }
                        } catch (...) {
                            std::cout << "[GCS] Error parsing query parameters." << std::endl;
                        }
                    }
                }
            }
        }
    });
    cmd_thread.detach();

    auto clock = platform::make_platform_clock();
    while (true) {
        network_mgr->tick(clock->now_ms());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return 0;
}
