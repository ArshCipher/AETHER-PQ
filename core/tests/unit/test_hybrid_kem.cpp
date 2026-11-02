// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_hybrid_kem.cpp — Unit tests for HybridKem

#include "uav_pqc/crypto/hybrid_kem.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::crypto;

struct HybridKemTest : ::testing::Test {
    HybridKem kem;
};

TEST_F(HybridKemTest, MetadataSizes) {
    // ML-KEM-768 pk = 1184, X25519 pk = 32
    EXPECT_EQ(kem.public_key_size(),    1216u);
    // ML-KEM-768 sk = 2400, X25519 sk = 32
    EXPECT_EQ(kem.private_key_size(),   2432u);
    // ML-KEM-768 ct = 1088, X25519 ct = 32
    EXPECT_EQ(kem.ciphertext_size(),    1120u);
    // HKDF output always 32
    EXPECT_EQ(kem.shared_secret_size(), 32u);
}

TEST_F(HybridKemTest, GenerateKeypair_CorrectSizes) {
    auto kp = kem.generate_keypair();
    ASSERT_TRUE(kp.has_value()) << kp.error().message;

    EXPECT_EQ(kp.value().public_key.size(),  kem.public_key_size());
    EXPECT_EQ(kp.value().private_key.size(), kem.private_key_size());
}

TEST_F(HybridKemTest, EncapDecap_SharedSecretsMatch) {
    auto kp = kem.generate_keypair();
    ASSERT_TRUE(kp.has_value());

    auto enc = kem.encapsulate(kp.value().public_key);
    ASSERT_TRUE(enc.has_value()) << enc.error().message;

    EXPECT_EQ(enc.value().ciphertext.size(),    kem.ciphertext_size());
    EXPECT_EQ(enc.value().shared_secret.size(), 32u);

    auto dec = kem.decapsulate(kp.value().private_key, enc.value().ciphertext);
    ASSERT_TRUE(dec.has_value()) << dec.error().message;

    EXPECT_EQ(
        std::vector<std::byte>(
            enc.value().shared_secret.data.data(),
            enc.value().shared_secret.data.data() + 32),
        std::vector<std::byte>(
            dec.value().data.data(),
            dec.value().data.data() + 32));
}

TEST_F(HybridKemTest, DifferentKeypairs_DifferentSharedSecrets) {
    auto kp1 = kem.generate_keypair();
    auto kp2 = kem.generate_keypair();
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());

    auto enc1 = kem.encapsulate(kp1.value().public_key);
    auto enc2 = kem.encapsulate(kp2.value().public_key);
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());

    EXPECT_NE(
        std::vector<std::byte>(
            enc1.value().shared_secret.data.data(),
            enc1.value().shared_secret.data.data() + 32),
        std::vector<std::byte>(
            enc2.value().shared_secret.data.data(),
            enc2.value().shared_secret.data.data() + 32));
}
