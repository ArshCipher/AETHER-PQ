// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_ecdsa_p256.cpp — Unit tests for ECDSA-P256

#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/common/types.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::crypto;

struct EcdsaP256Test : ::testing::Test {
    EcdsaP256 dsa;
};

TEST_F(EcdsaP256Test, KeypairSizes) {
    auto kp = dsa.generate_keypair();
    ASSERT_TRUE(kp.has_value()) << kp.error().message;
    EXPECT_EQ(kp.value().public_key.size(), 65u);
    EXPECT_EQ(kp.value().private_key.size(), 32u);
}

TEST_F(EcdsaP256Test, SignVerify_ValidMessage) {
    auto kp = dsa.generate_keypair();
    ASSERT_TRUE(kp.has_value());

    const auto msg = bytes_from_sv("Hello, UAV-PQC!");
    auto sig = dsa.sign(kp.value().private_key, ByteSpan{msg.data(), msg.size()});
    ASSERT_TRUE(sig.has_value()) << sig.error().message;

    auto ok = dsa.verify(kp.value().public_key, ByteSpan{msg.data(), msg.size()}, sig.value());
    ASSERT_TRUE(ok.has_value());
    EXPECT_TRUE(ok.value());
}

TEST_F(EcdsaP256Test, Verify_TamperedMessage) {
    auto kp = dsa.generate_keypair();
    ASSERT_TRUE(kp.has_value());

    const auto msg  = bytes_from_sv("Original");
    const auto msg2 = bytes_from_sv("Tampered");
    auto sig = dsa.sign(kp.value().private_key, ByteSpan{msg.data(), msg.size()});
    ASSERT_TRUE(sig.has_value());

    auto result = dsa.verify(kp.value().public_key, ByteSpan{msg2.data(), msg2.size()}, sig.value());
    if (result.has_value()) {
        EXPECT_FALSE(result.value());
    } else {
        EXPECT_EQ(result.error().code, ErrorCode::VerificationFailed);
    }
}

TEST_F(EcdsaP256Test, SignatureWithinMaxSize) {
    auto kp = dsa.generate_keypair();
    ASSERT_TRUE(kp.has_value());
    const auto msg = bytes_from_sv("size test");
    auto sig = dsa.sign(kp.value().private_key, ByteSpan{msg.data(), msg.size()});
    ASSERT_TRUE(sig.has_value());
    EXPECT_LE(sig.value().size(), dsa.max_signature_size());
}
