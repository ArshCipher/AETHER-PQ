// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// keygen.cpp — Developer utility to generate PQC and classical keys

#include "uav_pqc/uav_pqc.hpp"
#include <iostream>
#include <fstream>

using namespace uav_pqc;

bool save_file(const std::string& path, ByteSpan data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "UAV-PQC Key Generator Tool\n";
    std::cout << "==========================\n";

    // Initialize platform HAL
    auto hal = platform::make_platform_hal();
    logging::init(spdlog::level::info);

    // 1. Generate Hybrid KEM (ML-KEM-768 + X25519)
    crypto::HybridKem hkem("keygen-tool-context");
    auto hkem_kp_r = hkem.generate_keypair();
    if (!hkem_kp_r) {
        std::cerr << "Failed to generate Hybrid KEM key pair: " << hkem_kp_r.error().message << "\n";
        return 1;
    }
    std::cout << "[+] Generated Hybrid KEM (ML-KEM-768 + X25519) keys.\n";

    // 2. Generate ML-DSA-65
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto mldsa_kp_r = mldsa.generate_keypair();
    if (!mldsa_kp_r) {
        std::cerr << "Failed to generate ML-DSA keys: " << mldsa_kp_r.error().message << "\n";
        return 1;
    }
    std::cout << "[+] Generated ML-DSA-65 identity keys.\n";

    // 3. Generate ECDSA-P256
    crypto::EcdsaP256 ecdsa;
    auto ecdsa_kp_r = ecdsa.generate_keypair();
    if (!ecdsa_kp_r) {
        std::cerr << "Failed to generate ECDSA keys: " << ecdsa_kp_r.error().message << "\n";
        return 1;
    }
    std::cout << "[+] Generated ECDSA-P256 identity keys.\n";

    // Save public keys to check directory
    std::string prefix = "test_";
    if (argc > 1) {
        prefix = std::string(argv[1]) + "_";
    }

    save_file(prefix + "hybrid_kem.pub", hkem_kp_r.value().public_key.span());
    save_file(prefix + "hybrid_kem.priv", hkem_kp_r.value().private_key.span());
    save_file(prefix + "mldsa.pub", mldsa_kp_r.value().public_key.span());
    save_file(prefix + "mldsa.priv", mldsa_kp_r.value().private_key.span());
    save_file(prefix + "ecdsa.pub", ecdsa_kp_r.value().public_key.span());
    save_file(prefix + "ecdsa.priv", ecdsa_kp_r.value().private_key.span());

    std::cout << "[+] Keys saved with prefix: " << prefix << "\n";
    return 0;
}
