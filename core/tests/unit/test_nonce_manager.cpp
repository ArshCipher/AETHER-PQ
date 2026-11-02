// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_nonce_manager.cpp — Unit tests for NonceManager

#include "uav_pqc/session/nonce_manager.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::session;

TEST(NonceManagerTest, FirstNonce_ContainsPrefix) {
    std::array<std::byte, 4> prefix{std::byte{0xAA}, std::byte{0xBB},
                                     std::byte{0xCC}, std::byte{0xDD}};
    NonceManager mgr(prefix);

    auto nonce = mgr.next_nonce();
    ASSERT_TRUE(nonce.has_value());

    EXPECT_EQ(nonce.value()[0], std::byte{0xAA});
    EXPECT_EQ(nonce.value()[1], std::byte{0xBB});
    EXPECT_EQ(nonce.value()[2], std::byte{0xCC});
    EXPECT_EQ(nonce.value()[3], std::byte{0xDD});
}

TEST(NonceManagerTest, Nonces_AreMonotonicallyIncreasing) {
    std::array<std::byte, 4> prefix{};
    NonceManager mgr(prefix);

    auto n1 = mgr.next_nonce();
    auto n2 = mgr.next_nonce();
    ASSERT_TRUE(n1.has_value());
    ASSERT_TRUE(n2.has_value());

    // Counter bytes are at positions [4..11]; n2 counter > n1 counter
    EXPECT_NE(n1.value(), n2.value());
}

TEST(NonceManagerTest, Exhaustion_ReturnsError) {
    std::array<std::byte, 4> prefix{};
    NonceManager mgr(prefix, /*max_messages=*/2);

    EXPECT_TRUE(mgr.next_nonce().has_value());
    EXPECT_TRUE(mgr.next_nonce().has_value());
    const auto exhausted = mgr.next_nonce();
    EXPECT_FALSE(exhausted.has_value());
    EXPECT_EQ(exhausted.error().code, ErrorCode::NonceExhausted);
}

TEST(NonceManagerTest, AntiReplay_AcceptsNewNonce) {
    std::array<std::byte, 4> prefix{};
    NonceManager mgr(prefix);

    auto nonce = mgr.next_nonce();
    ASSERT_TRUE(nonce.has_value());
    EXPECT_TRUE(mgr.verify_and_advance(nonce.value()));
}

TEST(NonceManagerTest, AntiReplay_RejectsReusedNonce) {
    std::array<std::byte, 4> prefix{};
    NonceManager mgr(prefix);

    auto nonce = mgr.next_nonce();
    ASSERT_TRUE(nonce.has_value());
    EXPECT_TRUE(mgr.verify_and_advance(nonce.value()));
    // Second use of the same nonce → replay
    EXPECT_FALSE(mgr.verify_and_advance(nonce.value()));
}

TEST(NonceManagerTest, MessagesRemaining_DecreasesWithUse) {
    std::array<std::byte, 4> prefix{};
    NonceManager mgr(prefix, /*max_messages=*/10);

    EXPECT_EQ(mgr.messages_remaining(), 10u);
    mgr.next_nonce();
    EXPECT_EQ(mgr.messages_remaining(), 9u);
}
