// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/app/crypto_manager.hpp"
#include "nlohmann/json.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <memory>
#include <fstream>
#include <chrono>
#include <filesystem>
#include <thread>
#include <mutex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "cli_config.hpp"

using namespace uav_pqc;

// Standard Base64 encoding table
static const char* b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string der_to_pem(const std::vector<uint8_t>& der, const std::string& type) {
    std::string b64 = base64_encode(der);
    std::string out = "-----BEGIN " + type + "-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) {
        out += b64.substr(i, 64) + "\n";
    }
    out += "-----END " + type + "-----\n";
    return out;
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void backup_db(const uav_pqc::process_sim::NodeConfig& cfg, const std::string& db_path) {
    std::ifstream src(db_path, std::ios::binary);
    if (!src.is_open()) return;

    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::string backup_path = cfg.paths.pki_dir + "/backups/ca_backup_" + std::to_string(ts) + ".json";

    std::ofstream dst(backup_path, std::ios::binary);
    if (dst.is_open()) {
        dst << src.rdbuf();
    }
}

void write_pki_pems(const uav_pqc::process_sim::NodeConfig& cfg, const std::string& db_path) {
    try {
        std::ifstream f(db_path);
        if (!f.is_open()) return;
        nlohmann::json j;
        f >> j;
        f.close();

        // 1. Root Cert PEM
        if (j.contains("ca_cert") && !j["ca_cert"].get<std::string>().empty()) {
            auto cert_der = from_hex(j["ca_cert"].get<std::string>());
            std::ofstream cert_file(cfg.paths.pki_dir + "/root_cert.pem");
            if (cert_file.is_open()) {
                cert_file << der_to_pem(cert_der, "CERTIFICATE");
            }
        }

        // 2. Root Key PEM
        if (j.contains("ca_private_key") && !j["ca_private_key"].get<std::string>().empty()) {
            auto key_der = from_hex(j["ca_private_key"].get<std::string>());
            std::ofstream key_file(cfg.paths.pki_dir + "/root_key.pem");
            if (key_file.is_open()) {
                key_file << der_to_pem(key_der, "PRIVATE KEY");
            }
        }

        // 3. Write issued drone certs to issued/
        if (j.contains("issued_db") && j["issued_db"].is_array()) {
            for (size_t idx = 0; idx < j["issued_db"].size(); ++idx) {
                std::string cert_hex = j["issued_db"][idx].get<std::string>();
                auto der = from_hex(cert_hex);
                std::ofstream uav_file(cfg.paths.pki_dir + "/issued/cert_" + std::to_string(idx + 1) + ".pem");
                if (uav_file.is_open()) {
                    uav_file << der_to_pem(der, "CERTIFICATE");
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[CA] Warning: Failed to write PKI PEM files: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    auto cfg = uav_pqc::process_sim::parse_args(argc, argv);
    std::cout << "[CA] Initializing Certificate Authority process..." << std::endl;

    // Validate and create directories at startup
    validate_and_create_directories(cfg, true, false, false);

    std::string db_path = cfg.paths.pki_dir + "/ca.json";
    
    std::unique_ptr<app::CertificateAuthority> ca;
    std::ifstream check_file(db_path);
    if (check_file.good()) {
        check_file.close();
        ca = std::make_unique<app::CertificateAuthority>();
        std::cout << "[CA] Found existing database: " << db_path << ". Loading state..." << std::endl;
        auto load_r = ca->load_from_file(db_path);
        if (!load_r) {
            std::cerr << "[CA] Error: Failed to load existing database: " << load_r.error().message << std::endl;
            return 1;
        }
        std::cout << "[CA] State loaded successfully from: " << db_path << std::endl;
        // Make sure PEM files exist on startup
        write_pki_pems(cfg, db_path);
    } else {
        std::cout << "[CA] Database file not found. Generating new root..." << std::endl;
        NodeId ca_id{std::byte{0xCA}};
        app::CryptoManager crypto_mgr;
        auto ca_key = crypto_mgr.generate_dsa_keypair().value();
        ca = std::make_unique<app::CertificateAuthority>(ca_id, std::move(ca_key));
        auto root_cert_r = ca->generate_root_certificate("Root_CA", 31536000000ULL, 1000);
        if (!root_cert_r) {
            std::cerr << "[CA] Error: Failed to generate root certificate!" << std::endl;
            return 1;
        }
        // Atomic Save initial database
        auto save_r = ca->save_to_file(db_path + ".tmp");
        if (!save_r) {
            std::cerr << "[CA] Warning: Failed to save initial database to: " << db_path << ".tmp" << std::endl;
        } else {
            try {
                std::filesystem::rename(db_path + ".tmp", db_path);
                std::cout << "[CA] Initial database saved to: " << db_path << std::endl;
                write_pki_pems(cfg, db_path);
            } catch (const std::exception& e) {
                std::cerr << "[CA] Error during initial database atomic rename: " << e.what() << std::endl;
                return 1;
            }
        }
    }

    // Use SOCK_STREAM (TCP) so large registration packets (ML-DSA pubkey ~1952 bytes)
    // are delivered reliably without IP fragmentation over BATMAN-adv.
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "[CA] Error: Failed to create socket!" << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    uint16_t bind_port = cfg.local_port != 0 ? cfg.local_port : cfg.ca_port;
    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(bind_port);
    local_addr.sin_addr.s_addr = inet_addr(cfg.local_ip.c_str());

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
        std::cerr << "[CA] Error: Failed to bind socket to " << cfg.local_ip << ":" << bind_port << "!" << std::endl;
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 16) < 0) {
        std::cerr << "[CA] Error: Failed to listen on socket!" << std::endl;
        close(server_fd);
        return 1;
    }

    std::cout << "[CA] Certificate Authority listening on " << cfg.local_ip << ":" << bind_port << std::endl;

    // Mutex protecting CA state (cert issuance + DB writes) across threads
    std::mutex ca_mutex;

    while (true) {
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);
        int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&from_addr), &from_len);
        if (client_fd < 0) {
            std::cerr << "[CA] accept error" << std::endl;
            continue;
        }

        // Handle each registration in a separate thread — prevents one slow/malformed
        // client from blocking all other UAV registrations (ML-DSA signing takes ~50-200ms).
        auto* ca_raw = ca.get(); // raw ptr safe: ca outlives all threads
        std::thread([client_fd, ca_raw, &cfg, &db_path, &ca_mutex]() {
            // Set per-client receive timeout (10s to allow for slow BATMAN delivery)
            timeval tv{ 10, 0 };
            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            // Read full request from stream — stop once we have all pubkey bytes
            std::vector<uint8_t> buffer(65535);
            ssize_t received = 0;
            while (received < static_cast<ssize_t>(buffer.size())) {
                ssize_t n = recv(client_fd, buffer.data() + received, buffer.size() - received, 0);
                if (n <= 0) break;
                received += n;
                // Early termination: check if the full payload has arrived
                if (received > 37 && buffer[0] == 0x01) {
                    uint8_t name_len = buffer[33];
                    std::size_t offset = 34 + static_cast<std::size_t>(name_len);
                    if (received >= static_cast<ssize_t>(offset + 4)) {
                        uint32_t pubkey_len = 0;
                        std::memcpy(&pubkey_len, &buffer[offset], 4);
                        if (received >= static_cast<ssize_t>(offset + 4 + pubkey_len)) break;
                    }
                }
            }

            // Must be RegisterReq (0x01) with enough bytes
            if (received > 37 && buffer[0] == 0x01) {
                NodeId node_id{};
                std::copy(buffer.begin() + 1, buffer.begin() + 33,
                          reinterpret_cast<uint8_t*>(node_id.data()));

                uint8_t name_len = buffer[33];
                std::string name(reinterpret_cast<char*>(&buffer[34]), name_len);

                std::size_t offset = 34 + static_cast<std::size_t>(name_len);
                if (received >= static_cast<ssize_t>(offset + 4)) {
                    uint32_t pubkey_len = 0;
                    std::memcpy(&pubkey_len, &buffer[offset], 4);
                    offset += 4;

                    if (received >= static_cast<ssize_t>(offset + pubkey_len)) {
                        crypto::DsaPublicKey pub_key;
                        pub_key.data.resize(pubkey_len);
                        std::transform(buffer.begin() + static_cast<ssize_t>(offset),
                                       buffer.begin() + static_cast<ssize_t>(offset + pubkey_len),
                                       pub_key.data.begin(),
                                       [](uint8_t b) { return static_cast<std::byte>(b); });

                        // Serialize: cert issuance and DB writes
                        std::unique_lock<std::mutex> lock(ca_mutex);
                        std::cout << "[CA] Issuing certificate for Node: " << name << std::endl;
                        auto cert_r = ca_raw->issue_certificate(name, node_id,
                                                            crypto::DsaPublicKey{}, pub_key,
                                                            3600000, 1000);
                        if (cert_r) {
                            Bytes cert_bytes = cert_r.value().to_der();

                            backup_db(cfg, db_path);
                            auto save_r = ca_raw->save_to_file(db_path + ".tmp");
                            if (!save_r) {
                                std::cerr << "[CA] Warning: Failed to save DB: " << db_path << ".tmp" << std::endl;
                            } else {
                                try {
                                    std::filesystem::rename(db_path + ".tmp", db_path);
                                    write_pki_pems(cfg, db_path);
                                } catch (const std::exception& e) {
                                    std::cerr << "[CA] Warning: atomic rename failed: " << e.what() << std::endl;
                                }
                            }
                            lock.unlock(); // Release lock before network I/O

                            std::vector<uint8_t> reply;
                            reply.push_back(0x02); // RegisterAck
                            reply.insert(reply.end(),
                                         reinterpret_cast<uint8_t*>(cert_bytes.data()),
                                         reinterpret_cast<uint8_t*>(cert_bytes.data() + cert_bytes.size()));

                            ssize_t sent = 0;
                            while (sent < static_cast<ssize_t>(reply.size())) {
                                ssize_t n = send(client_fd, reply.data() + sent,
                                                 reply.size() - sent, 0);
                                if (n <= 0) break;
                                sent += n;
                            }
                        }
                    }
                }
            }
            close(client_fd);
        }).detach();
    }

    close(server_fd);
    return 0;
}

