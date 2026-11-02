// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// certgen.cpp — Developer utility to create custom DER certificates

#include "uav_pqc/uav_pqc.hpp"
#include <iostream>
#include <fstream>
#include <cstring>

using namespace uav_pqc;
using namespace uav_pqc::identity;

bool read_file(const std::string& path, Bytes& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    auto size = f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<std::size_t>(size));
    f.read(reinterpret_cast<char*>(out.data()), size);
    return true;
}

bool save_cert(const std::string& path, ByteSpan data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "UAV-PQC Certificate Generator Tool\n";
    std::cout << "==================================\n";

    if (argc < 4) {
        std::cerr << "Usage: uav_pqc_certgen <subject_name> <ecdsa_pub_path> <mldsa_pub_path> [out_cert_path]\n";
        return 1;
    }

    std::string subject_name = argv[1];
    std::string ecdsa_pub_path = argv[2];
    std::string mldsa_pub_path = argv[3];
    std::string out_path = "test_cert.der";
    if (argc > 4) {
        out_path = argv[4];
    }

    Bytes ecdsa_pub;
    if (!read_file(ecdsa_pub_path, ecdsa_pub)) {
        std::cerr << "Failed to read ECDSA public key: " << ecdsa_pub_path << "\n";
        return 1;
    }

    Bytes mldsa_pub;
    if (!read_file(mldsa_pub_path, mldsa_pub)) {
        std::cerr << "Failed to read ML-DSA public key: " << mldsa_pub_path << "\n";
        return 1;
    }

    // Build the custom DER TLV certificate structure
    Bytes cert;
    cert.push_back(std::byte{0x30}); // SEQUENCE
    // Length prefix (reserve 3 bytes for 2-byte length representation if needed)
    cert.push_back(std::byte{0x82});
    cert.push_back(std::byte{0x00});
    cert.push_back(std::byte{0x00});

    // UTF8String name (tag 0x0C)
    cert.push_back(std::byte{0x0C});
    cert.push_back(static_cast<std::byte>(subject_name.size()));
    for (char c : subject_name) cert.push_back(static_cast<std::byte>(c));

    // subject NodeID (tag 0x04)
    NodeId subject_id{};
    std::memset(subject_id.data(), 0x01, 16); // mock node id
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{16});
    cert.insert(cert.end(), subject_id.begin(), subject_id.end());

    // issuer NodeID (tag 0x04)
    NodeId issuer_id{};
    std::memset(issuer_id.data(), 0x02, 16); // mock issuer id
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{16});
    cert.insert(cert.end(), issuer_id.begin(), issuer_id.end());

    // not_before_ms (tag 0x02)
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{8});
    for (int i = 0; i < 8; ++i) cert.push_back(std::byte{0});

    // not_after_ms (tag 0x02)
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{8});
    for (int i = 0; i < 8; ++i) cert.push_back(std::byte{0xFF});

    // key_type (tag 0x02) -> Hybrid = 0x05
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{1});
    cert.push_back(std::byte{0x05});

    // ECDSA pub key (tag 0x04)
    cert.push_back(std::byte{0x04});
    cert.push_back(static_cast<std::byte>(ecdsa_pub.size()));
    cert.insert(cert.end(), ecdsa_pub.begin(), ecdsa_pub.end());

    // ML-DSA pub key (tag 0x04)
    cert.push_back(std::byte{0x04});
    // ML-DSA-65 public key size is 1952. Length is > 127, so we use 0x82 length format
    std::uint16_t mldsa_len = static_cast<std::uint16_t>(mldsa_pub.size());
    cert.push_back(std::byte{0x82});
    cert.push_back(static_cast<std::byte>((mldsa_len >> 8) & 0xFF));
    cert.push_back(static_cast<std::byte>(mldsa_len & 0xFF));
    cert.insert(cert.end(), mldsa_pub.begin(), mldsa_pub.end());

    // Fix up total SEQUENCE length (bytes after SEQUENCE length prefix, i.e. index 4 to end)
    std::uint16_t total_len = static_cast<std::uint16_t>(cert.size() - 4);
    cert[2] = static_cast<std::byte>((total_len >> 8) & 0xFF);
    cert[3] = static_cast<std::byte>(total_len & 0xFF);

    if (!save_cert(out_path, ByteSpan{cert.data(), cert.size()})) {
        std::cerr << "Failed to save certificate to: " << out_path << "\n";
        return 1;
    }

    std::cout << "[+] Saved certificate DER (" << cert.size() << " bytes) to: " << out_path << "\n";
    return 0;
}
