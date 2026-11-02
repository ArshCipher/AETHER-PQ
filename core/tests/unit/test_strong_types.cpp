// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/common/strong_types.hpp"

using namespace uav_pqc;

template <typename T>
void verify_roundtrip(T original) {
    // 1. Validate
    ASSERT_TRUE(original.validate().has_value());

    // 2. Binary serialize / deserialize roundtrip
    Bytes ser = original.serialize();
    auto deser_r = T::deserialize(ser);
    ASSERT_TRUE(deser_r.has_value()) << "Failed to deserialize " << typeid(T).name();
    EXPECT_EQ(deser_r.value(), original) << "Binary mismatch for " << typeid(T).name();

    // 3. JSON serialize / deserialize roundtrip
    nlohmann::json j = original.to_json();
    auto from_j_r = T::from_json(j);
    ASSERT_TRUE(from_j_r.has_value()) << "Failed from_json for " << typeid(T).name();
    EXPECT_EQ(from_j_r.value(), original) << "JSON mismatch for " << typeid(T).name();
}

TEST(StrongTypesTest, FundamentalAndPrimitiveTypes) {
    // 1. Timestamp
    verify_roundtrip(types::Timestamp(1717320000000ULL));

    // 2. NodeID
    NodeId nid_raw{};
    nid_raw[0] = std::byte{0x01};
    nid_raw[31] = std::byte{0x20};
    verify_roundtrip(types::NodeID(nid_raw));

    // 3. SessionID
    SessionId sid_raw{};
    sid_raw[0] = std::byte{0xAA};
    sid_raw[15] = std::byte{0xBB};
    verify_roundtrip(types::SessionID(sid_raw));

    // 4. Nonce
    std::array<std::byte, 12> nonce_raw{};
    nonce_raw[0] = std::byte{0x11};
    nonce_raw[11] = std::byte{0x22};
    verify_roundtrip(types::Nonce(nonce_raw));

    // 5. OperatingMode
    verify_roundtrip(types::OperatingMode(protocol::OperatingMode::Hybrid));
    verify_roundtrip(types::OperatingMode(protocol::OperatingMode::PqcOnly));

    // 6. CryptoProfile
    verify_roundtrip(types::CryptoProfile(policy::CryptographicProfile::Standard));
    verify_roundtrip(types::CryptoProfile(policy::CryptographicProfile::Hardened));

    // 7. CipherSuite
    protocol::CipherSuite cs = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    verify_roundtrip(types::CipherSuite(cs));

    // 8. ProtocolVersion
    verify_roundtrip(types::ProtocolVersion(1, 2));

    // 9. MissionType
    verify_roundtrip(types::MissionType(types::MissionType::Type::Military));

    // 10. BatteryStatus
    verify_roundtrip(types::BatteryStatus(85.5));
    // Invariant validation check
    EXPECT_FALSE(types::BatteryStatus(150.0).validate().has_value());

    // 11. NetworkMetrics
    verify_roundtrip(types::NetworkMetrics(25.4, 0.05));
    EXPECT_FALSE(types::NetworkMetrics(20.0, 1.5).validate().has_value());
}

TEST(StrongTypesTest, ComplexAndGroupTypes) {
    // 12. Certificate
    crypto::MlDsa dsa(crypto::MlDsa::Level::Dsa65);
    auto dsa_kp = dsa.generate_keypair().value();
    
    NodeId ca_id{};
    ca_id[0] = std::byte{0xCA};
    
    // We construct a valid certificate DER layout
    Bytes cert_der;
    cert_der.push_back(std::byte{0x30}); // SEQUENCE
    cert_der.push_back(std::byte{0x82});
    cert_der.push_back(std::byte{0x00});
    cert_der.push_back(std::byte{0x00});

    // name (tag 0x0C)
    std::string name = "CA_Root";
    cert_der.push_back(std::byte{0x0C});
    cert_der.push_back(static_cast<std::byte>(name.size()));
    for (char c : name) cert_der.push_back(static_cast<std::byte>(c));

    // subject ID (tag 0x04, 16 bytes)
    cert_der.push_back(std::byte{0x04});
    cert_der.push_back(std::byte{16});
    cert_der.insert(cert_der.end(), ca_id.begin(), ca_id.begin() + 16);

    // issuer ID (tag 0x04, 16 bytes)
    cert_der.push_back(std::byte{0x04});
    cert_der.push_back(std::byte{16});
    cert_der.insert(cert_der.end(), ca_id.begin(), ca_id.begin() + 16);

    // validity times (tag 0x02, 8 bytes)
    for (int t = 0; t < 2; ++t) {
        cert_der.push_back(std::byte{0x02});
        cert_der.push_back(std::byte{8});
        for (int i = 0; i < 8; ++i) cert_der.push_back(std::byte{0});
    }

    // key type (tag 0x02, 1 byte) -> MlDsa65 = 0x04
    cert_der.push_back(std::byte{0x02});
    cert_der.push_back(std::byte{1});
    cert_der.push_back(std::byte{0x04});

    // ML-DSA public key (tag 0x04, length prefix 0x82 due to size 1952)
    cert_der.push_back(std::byte{0x04});
    std::uint16_t mldsa_len = static_cast<std::uint16_t>(dsa_kp.public_key.data.size());
    cert_der.push_back(std::byte{0x82});
    cert_der.push_back(static_cast<std::byte>((mldsa_len >> 8) & 0xFF));
    cert_der.push_back(static_cast<std::byte>(mldsa_len & 0xFF));
    cert_der.insert(cert_der.end(), dsa_kp.public_key.data.begin(), dsa_kp.public_key.data.end());

    // Fix up total SEQUENCE length
    std::uint16_t total_len = static_cast<std::uint16_t>(cert_der.size() - 4);
    cert_der[2] = static_cast<std::byte>((total_len >> 8) & 0xFF);
    cert_der[3] = static_cast<std::byte>(total_len & 0xFF);

    auto cert_r = identity::Certificate::from_der(cert_der);
    ASSERT_TRUE(cert_r.has_value()) << cert_r.error().message;

    types::Certificate cert_wrap(cert_r.value());
    verify_roundtrip(cert_wrap);

    // 13. CertificateChain
    std::vector<identity::Certificate> chain_raw = {cert_r.value(), cert_r.value()};
    verify_roundtrip(types::CertificateChain(chain_raw));

    // 14. CertificateRevocation
    NodeId revoked_nid{};
    revoked_nid[0] = std::byte{0x0B};
    verify_roundtrip(types::CertificateRevocation(revoked_nid, 1717320000ULL));

    // 15. TreeNode
    crypto::KemPublicKey kem_pk;
    kem_pk.data.resize(32, std::byte{0x99});
    verify_roundtrip(types::TreeNode(5, kem_pk));

    // 16. PairwiseKey
    SecureBytes kb(32);
    std::fill_n(kb.data(), 32, std::byte{0x77});
    verify_roundtrip(types::PairwiseKey(std::move(kb)));

    // 17. GroupKey
    SecureBytes gkb(32);
    std::fill_n(gkb.data(), 32, std::byte{0x88});
    group::GroupKey gk(4, std::move(gkb), protocol::AeadAlgorithm::AesGcm256, 1000, 5000);
    // Since GroupKey is move-only, verify_roundtrip will move it
    verify_roundtrip(types::GroupKey(std::move(gk)));

    // 18. Session
    SessionId sid{};
    sid[0] = std::byte{0xAA};
    NodeId peer_id{};
    peer_id[0] = std::byte{0xBB};
    protocol::CipherSuite suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    crypto::AeadKey send_key = crypto::AeadKey::from_bytes(std::vector<std::byte>(32, std::byte{1}));
    crypto::AeadKey recv_key = crypto::AeadKey::from_bytes(std::vector<std::byte>(32, std::byte{2}));
    session::Session sess(sid, peer_id, suite, std::move(send_key), std::move(recv_key), {}, {}, 100000);
    // Since Session is move-only, verify_roundtrip will move it
    verify_roundtrip(types::Session(std::move(sess)));

    // 19. PacketHeader
    verify_roundtrip(types::PacketHeader(0x01, sid, 12345, 100));

    // 20. Packet
    verify_roundtrip(types::Packet(types::PacketHeader(0x01, sid, 12345, 2), {std::byte{0xAA}, std::byte{0xBB}}));
}
