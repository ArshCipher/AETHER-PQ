// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file test_ml_kem.cpp
 * @brief Unit tests for ML-KEM (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
 */

#include "uav_pqc/crypto/ml_kem.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::crypto;

// ── Fixture ───────────────────────────────────────────────────────────────────

class MlKemTest : public ::testing::TestWithParam<MlKem::Level> {
protected:
    MlKem kem{GetParam()};
};

INSTANTIATE_TEST_SUITE_P(AllLevels, MlKemTest,
    ::testing::Values(MlKem::Level::Kem512, MlKem::Level::Kem768, MlKem::Level::Kem1024),
    [](const ::testing::TestParamInfo<MlKem::Level>& info) {
        switch (info.param) {
            case MlKem::Level::Kem512:  return "Kem512";
            case MlKem::Level::Kem768:  return "Kem768";
            case MlKem::Level::Kem1024: return "Kem1024";
        }
        return "Unknown";
    });

// ── Tests ─────────────────────────────────────────────────────────────────────

TEST_P(MlKemTest, GenerateKeypair_SizesMatchMetadata) {
    const auto kp = kem.generate_keypair();
    ASSERT_TRUE(kp.has_value()) << kp.error().message;

    EXPECT_EQ(kp.value().public_key.size(),  kem.public_key_size());
    EXPECT_EQ(kp.value().private_key.size(), kem.private_key_size());
}

TEST_P(MlKemTest, EncapDecap_SharedSecretsMatch) {
    const auto kp = kem.generate_keypair();
    ASSERT_TRUE(kp.has_value());

    const auto encap = kem.encapsulate(kp.value().public_key);
    ASSERT_TRUE(encap.has_value()) << encap.error().message;

    EXPECT_EQ(encap.value().ciphertext.size(),    kem.ciphertext_size());
    EXPECT_EQ(encap.value().shared_secret.size(), kem.shared_secret_size());

    const auto decap = kem.decapsulate(kp.value().private_key, encap.value().ciphertext);
    ASSERT_TRUE(decap.has_value()) << decap.error().message;

    EXPECT_EQ(encap.value().shared_secret.size(), decap.value().size());
    EXPECT_EQ(
        std::vector<std::byte>(
            encap.value().shared_secret.data.data(),
            encap.value().shared_secret.data.data() + encap.value().shared_secret.size()),
        std::vector<std::byte>(
            decap.value().data.data(),
            decap.value().data.data() + decap.value().size()));
}

TEST_P(MlKemTest, Encapsulate_WrongKeySizeReturnsError) {
    KemPublicKey bad_pk;
    bad_pk.data.resize(kem.public_key_size() - 1); // wrong size

    const auto result = kem.encapsulate(bad_pk);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArgument);
}

TEST_P(MlKemTest, Decapsulate_WrongCiphertextSizeReturnsError) {
    const auto kp = kem.generate_keypair();
    ASSERT_TRUE(kp.has_value());

    KemCiphertext bad_ct;
    bad_ct.data.resize(kem.ciphertext_size() - 1);

    const auto result = kem.decapsulate(kp.value().private_key, bad_ct);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidArgument);
}

TEST_P(MlKemTest, TwoKeypairs_DifferentPublicKeys) {
    const auto kp1 = kem.generate_keypair();
    const auto kp2 = kem.generate_keypair();
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());

    EXPECT_NE(kp1.value().public_key.data, kp2.value().public_key.data);
}

TEST_P(MlKemTest, AlgorithmIdIsNonEmpty) {
    EXPECT_FALSE(kem.algorithm_id().empty());
}

TEST_P(MlKemTest, SharedSecretIsAlways32Bytes) {
    EXPECT_EQ(kem.shared_secret_size(), 32u);
}
