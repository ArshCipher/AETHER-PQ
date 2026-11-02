// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_x25519.cpp — Unit tests for X25519Kem

#include "uav_pqc/crypto/x25519.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::crypto;

TEST(X25519KemTest, KeypairSizes) {
    X25519Kem kem;
    auto kp = kem.generate_keypair();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp.value().public_key.size(),  32u);
    EXPECT_EQ(kp.value().private_key.size(), 32u);
}

TEST(X25519KemTest, EncapDecap_SharedSecretsMatch) {
    X25519Kem kem;
    auto alice = kem.generate_keypair();
    ASSERT_TRUE(alice.has_value());

    auto enc = kem.encapsulate(alice.value().public_key);
    ASSERT_TRUE(enc.has_value());
    EXPECT_EQ(enc.value().ciphertext.size(),    32u); // ephemeral pk
    EXPECT_EQ(enc.value().shared_secret.size(), 32u);

    auto dec = kem.decapsulate(alice.value().private_key, enc.value().ciphertext);
    ASSERT_TRUE(dec.has_value());

    EXPECT_EQ(
        std::vector<std::byte>(
            enc.value().shared_secret.data.data(),
            enc.value().shared_secret.data.data() + 32),
        std::vector<std::byte>(
            dec.value().data.data(),
            dec.value().data.data() + 32));
}

TEST(X25519KemTest, TwoEncapsulations_DifferentSharedSecrets) {
    X25519Kem kem;
    auto alice = kem.generate_keypair();
    ASSERT_TRUE(alice.has_value());

    auto enc1 = kem.encapsulate(alice.value().public_key);
    auto enc2 = kem.encapsulate(alice.value().public_key);
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());

    // Different ephemeral keys → different shared secrets
    EXPECT_NE(
        std::vector<std::byte>(
            enc1.value().shared_secret.data.data(),
            enc1.value().shared_secret.data.data() + 32),
        std::vector<std::byte>(
            enc2.value().shared_secret.data.data(),
            enc2.value().shared_secret.data.data() + 32));
}
