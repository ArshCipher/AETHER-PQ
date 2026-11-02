// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_session.cpp — Unit tests for Session (encrypt/decrypt)

#include "uav_pqc/session/session.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::session;
using namespace uav_pqc::crypto;

static Session make_test_session(protocol::AeadAlgorithm alg) {
    SessionId id{};
    id[0] = std::byte{0x01};
    NodeId peer{};
    peer[0] = std::byte{0x02};

    auto suite = protocol::CipherSuite::make_hybrid(alg);

    const std::size_t key_len = suite.aead_key_size();
    AeadKey send_key;
    send_key.data.resize(key_len);
    std::fill(send_key.data.data(), send_key.data.data() + send_key.data.size(), std::byte{0xAA});
    AeadKey recv_key;
    recv_key.data.resize(key_len);
    std::fill(recv_key.data.data(), recv_key.data.data() + recv_key.data.size(), std::byte{0xAA});

    std::array<std::byte, 4> send_prefix{std::byte{0x01}, std::byte{0x02},
                                          std::byte{0x03}, std::byte{0x04}};
    std::array<std::byte, 4> recv_prefix{std::byte{0x01}, std::byte{0x02},
                                          std::byte{0x03}, std::byte{0x04}};

    return Session{id, peer, suite,
                   std::move(send_key), std::move(recv_key),
                   send_prefix, recv_prefix, UINT64_MAX};
}

class SessionTest : public ::testing::TestWithParam<protocol::AeadAlgorithm> {};

INSTANTIATE_TEST_SUITE_P(Algorithms, SessionTest,
    ::testing::Values(
        protocol::AeadAlgorithm::AesGcm256,
        protocol::AeadAlgorithm::ChaCha20Poly),
    [](const auto& info) {
        return info.param == protocol::AeadAlgorithm::AesGcm256
               ? "AesGcm256" : "ChaCha20Poly";
    });

TEST_P(SessionTest, EncryptDecrypt_Loopback) {
    auto session = make_test_session(GetParam());

    const auto plaintext = bytes_from_sv("UAV telemetry payload");
    const auto aad       = bytes_from_sv("msg-header");

    auto wire = session.encrypt(ByteSpan{plaintext.data(), plaintext.size()},
                                ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(wire.has_value()) << wire.error().message;
    EXPECT_GT(wire.value().size(), plaintext.size()); // nonce + ciphertext + tag

    auto recovered = session.decrypt(ByteSpan{wire.value().data(), wire.value().size()},
                                     ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(recovered.has_value()) << recovered.error().message;
    EXPECT_EQ(recovered.value(), plaintext);
}

TEST_P(SessionTest, Replay_Rejected) {
    auto session = make_test_session(GetParam());

    const auto pt  = bytes_from_sv("msg");
    const auto aad = bytes_from_sv("");

    auto wire = session.encrypt(ByteSpan{pt.data(), pt.size()}, ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(wire.has_value());

    // First decrypt: success
    auto r1 = session.decrypt(ByteSpan{wire.value().data(), wire.value().size()},
                               ByteSpan{aad.data(), aad.size()});
    EXPECT_TRUE(r1.has_value());

    // Replay: second decrypt of same wire message fails
    auto r2 = session.decrypt(ByteSpan{wire.value().data(), wire.value().size()},
                               ByteSpan{aad.data(), aad.size()});
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error().code, ErrorCode::ReplayDetected);
}
