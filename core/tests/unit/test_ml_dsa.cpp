// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file test_ml_dsa.cpp
 * @brief Unit tests for ML-DSA (ML-DSA-44, ML-DSA-65, ML-DSA-87).
 */

#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/common/types.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::crypto;

class MlDsaTest : public ::testing::TestWithParam<MlDsa::Level> {
protected:
    MlDsa dsa{GetParam()};
};

INSTANTIATE_TEST_SUITE_P(AllLevels, MlDsaTest,
    ::testing::Values(MlDsa::Level::Dsa44, MlDsa::Level::Dsa65, MlDsa::Level::Dsa87),
    [](const ::testing::TestParamInfo<MlDsa::Level>& info) {
        switch (info.param) {
            case MlDsa::Level::Dsa44: return "Dsa44";
            case MlDsa::Level::Dsa65: return "Dsa65";
            case MlDsa::Level::Dsa87: return "Dsa87";
        }
        return "Unknown";
    });

TEST_P(MlDsaTest, GenerateKeypair_SizesMatchMetadata) {
    const auto kp = dsa.generate_keypair();
    ASSERT_TRUE(kp.has_value()) << kp.error().message;

    EXPECT_EQ(kp.value().public_key.size(),  dsa.public_key_size());
    EXPECT_EQ(kp.value().private_key.size(), dsa.private_key_size());
}

TEST_P(MlDsaTest, SignVerify_ValidSignature) {
    const auto kp = dsa.generate_keypair();
    ASSERT_TRUE(kp.has_value());

    const Bytes message = bytes_from_sv("The quick brown fox jumps over the lazy dog");
    const auto sig = dsa.sign(kp.value().private_key, ByteSpan{message.data(), message.size()});
    ASSERT_TRUE(sig.has_value()) << sig.error().message;
    EXPECT_FALSE(sig.value().data.empty());

    const auto result = dsa.verify(kp.value().public_key,
        ByteSpan{message.data(), message.size()}, sig.value());
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
}

TEST_P(MlDsaTest, Verify_InvalidSignature) {
    const auto kp = dsa.generate_keypair();
    ASSERT_TRUE(kp.has_value());

    const Bytes message = bytes_from_sv("Valid message");
    const auto sig = dsa.sign(kp.value().private_key, ByteSpan{message.data(), message.size()});
    ASSERT_TRUE(sig.has_value());

    const Bytes tampered = bytes_from_sv("Tampered message");
    const auto result = dsa.verify(kp.value().public_key,
        ByteSpan{tampered.data(), tampered.size()}, sig.value());

    // Either returns an error or returns false
    if (result.has_value()) {
        EXPECT_FALSE(result.value());
    } else {
        EXPECT_EQ(result.error().code, ErrorCode::VerificationFailed);
    }
}

TEST_P(MlDsaTest, Verify_WrongPublicKey) {
    const auto kp1 = dsa.generate_keypair();
    const auto kp2 = dsa.generate_keypair();
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());

    const Bytes message = bytes_from_sv("Test message");
    const auto sig = dsa.sign(kp1.value().private_key, ByteSpan{message.data(), message.size()});
    ASSERT_TRUE(sig.has_value());

    // Verify with wrong key
    const auto result = dsa.verify(kp2.value().public_key,
        ByteSpan{message.data(), message.size()}, sig.value());
    if (result.has_value()) {
        EXPECT_FALSE(result.value());
    }
}

TEST_P(MlDsaTest, SignatureIsWithinMaxSize) {
    const auto kp = dsa.generate_keypair();
    ASSERT_TRUE(kp.has_value());

    const Bytes msg = bytes_from_sv("size check");
    const auto sig = dsa.sign(kp.value().private_key, ByteSpan{msg.data(), msg.size()});
    ASSERT_TRUE(sig.has_value());
    EXPECT_LE(sig.value().size(), dsa.max_signature_size());
}
