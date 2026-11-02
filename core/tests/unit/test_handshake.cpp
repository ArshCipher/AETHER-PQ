// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_handshake.cpp — Unit tests for Handshake state machine

#include "uav_pqc/protocol/handshake.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::protocol;

static HandshakeConfig make_test_config(bool is_client) {
    HandshakeConfig cfg;
    cfg.offered_modes = {OperatingMode::Hybrid, OperatingMode::Transition};
    cfg.our_node_id = {is_client ? std::byte{0x01} : std::byte{0x02}};

    // Generate certificates and keys
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto ml_kp = mldsa.generate_keypair().value();
    cfg.our_ml_dsa_private_key = std::move(ml_kp.private_key);

    crypto::EcdsaP256 ecdsa;
    auto ec_kp = ecdsa.generate_keypair().value();
    cfg.our_dsa_private_key = std::move(ec_kp.private_key);

    // Create a dummy DER cert using our parsing logic format:
    // SEQUENCE (0x30), length, UTF8String (0x0C) name, OCTET STRING (0x04) node_id...
    // To make it easy, we construct a manual certificate byte representation.
    // Bytes structure:
    // 0x30 (SEQUENCE)
    // 0x82, 0x00, 0xAA (length)
    // 0x0C (UTF8String), 0x0B (length), 'U','A','V','-','P','Q','C','-','N','o','d','e'
    // 0x04 (OCTET_STRING), 0x10 (length), 16 bytes node_id
    // 0x04 (OCTET_STRING), 0x10 (length), 16 bytes issuer_id
    // 0x02 (INTEGER), 0x08 (length), 8 bytes not_before
    // 0x02 (INTEGER), 0x08 (length), 8 bytes not_after
    // 0x02 (INTEGER), 0x01 (length), 0x05 (CertKeyType::Hybrid)
    // 0x04 (OCTET_STRING), 0x41 (length), 65 bytes ECDSA pub key
    // 0x04 (OCTET_STRING), 0x82 (length), length, ML-DSA pub key bytes
    Bytes cert;
    cert.push_back(std::byte{0x30}); // SEQUENCE
    cert.push_back(std::byte{0x82});
    cert.push_back(std::byte{0x01});
    cert.push_back(std::byte{0xFF}); // Dummy length

    // UTF8String name
    cert.push_back(std::byte{0x0C});
    cert.push_back(std::byte{12});
    const char* name = "UAV-PQC-Node";
    for (int i = 0; i < 12; ++i) cert.push_back(static_cast<std::byte>(name[i]));

    // subject NodeID
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{16});
    cert.insert(cert.end(), 16, is_client ? std::byte{0x01} : std::byte{0x02});

    // issuer NodeID
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{16});
    cert.insert(cert.end(), 16, std::byte{0x03}); // CA id

    // not_before
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{8});
    cert.insert(cert.end(), 8, std::byte{0});

    // not_after
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{8});
    cert.insert(cert.end(), 8, std::byte{0xFF}); // valid indefinitely

    // key_type (Hybrid = 0x05)
    cert.push_back(std::byte{0x02});
    cert.push_back(std::byte{1});
    cert.push_back(std::byte{0x05});

    // ECDSA pub key
    cert.push_back(std::byte{0x04});
    cert.push_back(std::byte{65});
    cert.insert(cert.end(), ec_kp.public_key.data.begin(), ec_kp.public_key.data.end());

    // ML-DSA pub key
    cert.push_back(std::byte{0x04});
    // ML-DSA-65 public key size is 1952 bytes. Let's write length prefix 1952 (0x07A0)
    cert.push_back(std::byte{0x82});
    cert.push_back(std::byte{0x07});
    cert.push_back(std::byte{0xA0});
    cert.insert(cert.end(), ml_kp.public_key.data.begin(), ml_kp.public_key.data.end());

    // Fix up total SEQUENCE length
    std::uint16_t total_len = static_cast<std::uint16_t>(cert.size() - 4);
    cert[2] = static_cast<std::byte>((total_len >> 8) & 0xFF);
    cert[3] = static_cast<std::byte>(total_len & 0xFF);

    cfg.our_certificate = cert;
    cfg.trusted_ca_certs.push_back(cert); // trust our self-signed root cert for this test

    return cfg;
}

TEST(HandshakeTest, CompleteExchange) {
    auto client_cfg = make_test_config(true);
    auto server_cfg = make_test_config(false);

    auto initiator = make_handshake(HandshakeRole::Initiator, std::move(client_cfg));
    auto responder = make_handshake(HandshakeRole::Responder, std::move(server_cfg));

    auto send_to_responder = [&](Bytes msg) -> VoidResult {
        return responder->feed_message(msg);
    };

    auto send_to_initiator = [&](Bytes msg) -> VoidResult {
        return initiator->feed_message(msg);
    };

    initiator->set_send_fn(send_to_responder);
    responder->set_send_fn(send_to_initiator);

    // Start initiator
    EXPECT_EQ(initiator->state(), HandshakeState::Idle);
    EXPECT_EQ(responder->state(), HandshakeState::Idle);

    auto r = initiator->start();
    ASSERT_TRUE(r.has_value()) << r.error().message;

    // Both should now be Complete because the synchronous send callbacks executed the entire flow!
    EXPECT_EQ(initiator->state(), HandshakeState::Complete);
    EXPECT_EQ(responder->state(), HandshakeState::Complete);

    // Verify session outputs
    auto client_res = initiator->result();
    ASSERT_TRUE(client_res.has_value());
    EXPECT_EQ(client_res.value().negotiated_mode, OperatingMode::Hybrid);
}

// ── SessionEstablishment Tests ───────────────────────────────────────────────
#include "uav_pqc/protocol/session_establishment.hpp"

static EstablishmentConfig make_establishment_test_config(bool is_client, OperatingMode mode) {
    EstablishmentConfig ec;
    ec.handshake = make_test_config(is_client);
    ec.handshake.offered_modes = {mode};
    ec.session_lifetime_ms = 3600 * 1000;
    return ec;
}

TEST(SessionEstablishmentTest, AllFourModes) {
    std::vector<OperatingMode> modes = {
        OperatingMode::Classical,
        OperatingMode::Transition,
        OperatingMode::Hybrid,
        OperatingMode::PqcOnly
    };

    for (auto mode : modes) {
        auto client_cfg = make_establishment_test_config(true, mode);
        auto server_cfg = make_establishment_test_config(false, mode);

        auto initiator = make_session_establisher(HandshakeRole::Initiator, std::move(client_cfg));
        auto responder = make_session_establisher(HandshakeRole::Responder, std::move(server_cfg));

        initiator->set_send_fn([&](Bytes msg) -> VoidResult {
            return responder->feed_message(msg);
        });
        responder->set_send_fn([&](Bytes msg) -> VoidResult {
            return initiator->feed_message(msg);
        });

        EXPECT_EQ(initiator->state(), EstablishmentState::Idle);
        EXPECT_EQ(responder->state(), EstablishmentState::Idle);

        auto start_r = initiator->start();
        ASSERT_TRUE(start_r.has_value()) << start_r.error().message;

        EXPECT_EQ(initiator->state(), EstablishmentState::Complete);
        EXPECT_EQ(responder->state(), EstablishmentState::Complete);

        auto client_res_r = initiator->result();
        ASSERT_TRUE(client_res_r.has_value()) << client_res_r.error().message;

        auto server_res_r = responder->result();
        ASSERT_TRUE(server_res_r.has_value()) << server_res_r.error().message;

        auto& client_sess = client_res_r.value().session;
        auto& server_sess = server_res_r.value().session;

        // Perform loopback encryption and decryption to verify session keys
        Bytes plaintext = bytes_from_sv("Heterogeneous UAV PQC Network Test Payload");
        Bytes aad = bytes_from_sv("Test AAD");
        auto encrypt_r = client_sess.encrypt(plaintext, aad);
        ASSERT_TRUE(encrypt_r.has_value()) << encrypt_r.error().message;

        auto decrypt_r = server_sess.decrypt(encrypt_r.value(), aad);
        ASSERT_TRUE(decrypt_r.has_value()) << decrypt_r.error().message;

        EXPECT_EQ(decrypt_r.value(), plaintext);
    }
}

