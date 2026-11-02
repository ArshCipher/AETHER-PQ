// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include "uav_pqc/session/secure_comm.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/common/logging.hpp"

using namespace uav_pqc;
using namespace uav_pqc::session;

namespace {

// Helper to construct a mock Session
std::shared_ptr<Session> make_mock_session(protocol::AeadAlgorithm aead_alg) {
    SessionId sid = {std::byte{0x01}};
    NodeId peer = {std::byte{0x02}};
    
    protocol::CipherSuite suite;
    suite.aead_algorithm = aead_alg;
    suite.max_messages_per_key = 1000;
    suite.max_session_seconds = 3600;

    std::size_t klen = (aead_alg == protocol::AeadAlgorithm::AesGcm128) ? 16 : 32;
    crypto::AeadKey send_key = crypto::AeadKey::from_bytes(Bytes(klen, std::byte{0xA1}));
    crypto::AeadKey recv_key = crypto::AeadKey::from_bytes(Bytes(klen, std::byte{0xA1})); // loopback keys

    std::array<std::byte, 4> send_prefix = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
    std::array<std::byte, 4> recv_prefix = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};

    return std::make_shared<Session>(
        sid, peer, suite, std::move(send_key), std::move(recv_key),
        send_prefix, recv_prefix, 9999999999ULL
    );
}

} // namespace

// ── Test 1: Encrypt/Decrypt Roundtrip for All Categories ─────────────────────
TEST(SecureCommTest, EncryptDecryptRoundtripAllCategories) {
    auto session = make_mock_session(protocol::AeadAlgorithm::AesGcm256);
    SecureCommLayer layer(session, 500);

    const std::vector<AppCategory> categories = {
        AppCategory::Telemetry,
        AppCategory::Commands,
        AppCategory::Video,
        AppCategory::Payload,
        AppCategory::Firmware,
        AppCategory::MissionUpdates
    };

    transport::StreamId stream_id = 100;
    for (auto cat : categories) {
        AppMessage original{
            .category = cat,
            .payload = bytes_from_sv("Hello Secure UAV Packet Category: " + std::to_string(static_cast<int>(cat)))
        };

        // Encrypt & Fragment
        auto frags_r = layer.protect_and_fragment(original, stream_id++, {});
        ASSERT_TRUE(frags_r.has_value());
        ASSERT_FALSE(frags_r.value().empty());

        // Process fragments (should yield std::nullopt until the last one)
        std::optional<AppMessage> reassembled;
        for (const auto& frag : frags_r.value()) {
            auto proc_r = layer.process_incoming_fragment(frag, 1000, {});
            ASSERT_TRUE(proc_r.has_value()) << proc_r.error().message;
            if (proc_r.value().has_value()) {
                reassembled = std::move(proc_r.value().value());
            }
        }

        ASSERT_TRUE(reassembled.has_value());
        EXPECT_EQ(reassembled->category, original.category);
        EXPECT_EQ(reassembled->payload, original.payload);
    }
}

// ── Test 2: Large Message Fragmentation and Reassembly ───────────────────────
TEST(SecureCommTest, LargeMessageFragmentationAndReassembly) {
    auto session = make_mock_session(protocol::AeadAlgorithm::ChaCha20Poly);
    SecureCommLayer layer(session, 150); // small MTU to force multiple fragments

    // 1000-byte firmware binary
    Bytes large_payload(1000, std::byte{0x55});
    AppMessage original{
        .category = AppCategory::Firmware,
        .payload = large_payload
    };

    auto frags_r = layer.protect_and_fragment(original, 42, {});
    ASSERT_TRUE(frags_r.has_value());
    // ciphertext will be around ~1028 bytes (1 byte category + 12 nonce + 16 tag + payload)
    // MTU is 150, so fragment payload limit is 146 bytes (150 - 4 header)
    // 1028 / 146 should yield around 8 fragments
    EXPECT_GT(frags_r.value().size(), 1u);

    std::optional<AppMessage> reassembled;
    for (size_t i = 0; i < frags_r.value().size(); ++i) {
        auto proc_r = layer.process_incoming_fragment(frags_r.value()[i], 1000, {});
        ASSERT_TRUE(proc_r.has_value()) << proc_r.error().message;
        if (i == frags_r.value().size() - 1) {
            EXPECT_TRUE(proc_r.value().has_value());
            reassembled = std::move(proc_r.value().value());
        } else {
            EXPECT_FALSE(proc_r.value().has_value());
        }
    }

    ASSERT_TRUE(reassembled.has_value());
    EXPECT_EQ(reassembled->category, AppCategory::Firmware);
    EXPECT_EQ(reassembled->payload, large_payload);
}

// ── Test 3: Replay Rejection ──────────────────────────────────────────────────
TEST(SecureCommTest, ReplayRejection) {
    auto session = make_mock_session(protocol::AeadAlgorithm::AesGcm128);
    SecureCommLayer layer(session, 500);

    AppMessage msg{
        .category = AppCategory::Commands,
        .payload = bytes_from_sv("Critical Land Command")
    };

    auto frags_r = layer.protect_and_fragment(msg, 99, {});
    ASSERT_TRUE(frags_r.has_value());

    // Feed once: OK
    std::optional<AppMessage> reassembled;
    for (const auto& frag : frags_r.value()) {
        auto proc_r = layer.process_incoming_fragment(frag, 1000, {});
        ASSERT_TRUE(proc_r.has_value()) << proc_r.error().message;
        if (proc_r.value().has_value()) {
            reassembled = std::move(proc_r.value().value());
        }
    }
    ASSERT_TRUE(reassembled.has_value());

    // Feed again (replay): must be rejected
    for (const auto& frag : frags_r.value()) {
        auto proc_r = layer.process_incoming_fragment(frag, 1000, {});
        // Decryption fails or Replay detected depending on which fragment triggers complete decryption.
        // The last fragment completes reassembly and invokes decrypt() which does the anti-replay window checks.
        if (proc_r.has_value() && proc_r.value().has_value()) {
            // It should NOT succeed
            FAIL() << "Replayed message was decrypted successfully!";
        } else if (!proc_r.has_value()) {
            EXPECT_EQ(proc_r.error().code, ErrorCode::ReplayDetected);
            return;
        }
    }
    FAIL() << "Did not catch replay rejection error";
}

// ── Test 4: Integrity Verification Failure ───────────────────────────────────
TEST(SecureCommTest, IntegrityVerificationFailure) {
    auto session = make_mock_session(protocol::AeadAlgorithm::AesGcm256);
    SecureCommLayer layer(session, 500);

    AppMessage msg{
        .category = AppCategory::Telemetry,
        .payload = bytes_from_sv("Speed 12 m/s")
    };

    auto frags_r = layer.protect_and_fragment(msg, 101, {});
    ASSERT_TRUE(frags_r.has_value());

    // Corrupt a byte in the payload of the first fragment
    ASSERT_FALSE(frags_r.value().empty());
    ASSERT_GE(frags_r.value()[0].payload.size(), 1u);
    frags_r.value()[0].payload[0] ^= std::byte{0xFF}; // flip bits

    // Processing fragments should fail decryption on the last fragment
    for (const auto& frag : frags_r.value()) {
        auto proc_r = layer.process_incoming_fragment(frag, 1000, {});
        if (!proc_r.has_value()) {
            EXPECT_NE(proc_r.error().code, ErrorCode::Ok);
            return;
        }
    }
    FAIL() << "Corrupted packet did not fail decryption!";
}
