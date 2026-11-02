// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_aes_gcm.cpp — Unit tests for AES-GCM AEAD

#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/common/types.hpp"
#include <gtest/gtest.h>
#include <array>

using namespace uav_pqc;
using namespace uav_pqc::crypto;

class AesGcmTest : public ::testing::TestWithParam<AesKeyLen> {
protected:
    AesGcm aead{GetParam()};
};

INSTANTIATE_TEST_SUITE_P(KeyLengths, AesGcmTest,
    ::testing::Values(AesKeyLen::Aes128, AesKeyLen::Aes256),
    [](const auto& info) { return info.param == AesKeyLen::Aes256 ? "AES256" : "AES128"; });

TEST_P(AesGcmTest, EncryptDecrypt_RoundTrip) {
    const std::size_t key_len = aead.key_size();
    AeadKey key;
    key.data.resize(key_len);
    std::fill(key.data.data(), key.data.data() + key.data.size(), std::byte{0x42});

    std::array<std::byte, 12> nonce{};
    nonce[11] = std::byte{0x01};

    const auto plaintext = bytes_from_sv("Hello, encrypted world!");
    const auto aad       = bytes_from_sv("header-bytes");

    auto ct = aead.encrypt(key, ByteSpan{nonce.data(), nonce.size()},
                           ByteSpan{plaintext.data(), plaintext.size()},
                           ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(ct.has_value()) << ct.error().message;
    EXPECT_EQ(ct.value().size(), plaintext.size() + aead.tag_size());

    auto pt = aead.decrypt(key, ByteSpan{nonce.data(), nonce.size()},
                           ByteSpan{ct.value().data(), ct.value().size()},
                           ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(pt.has_value()) << pt.error().message;
    EXPECT_EQ(pt.value(), plaintext);
}

TEST_P(AesGcmTest, Decrypt_WrongTag_Fails) {
    AeadKey key;
    key.data.resize(aead.key_size());
    std::fill(key.data.data(), key.data.data() + key.data.size(), std::byte{0x11});
    std::array<std::byte, 12> nonce{};

    const auto plaintext = bytes_from_sv("secret");
    const auto aad       = bytes_from_sv("aad");

    auto ct = aead.encrypt(key, ByteSpan{nonce.data(), 12},
                           ByteSpan{plaintext.data(), plaintext.size()},
                           ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(ct.has_value());

    // Flip a byte in the tag
    ct.value().back() = ~ct.value().back();

    auto pt = aead.decrypt(key, ByteSpan{nonce.data(), 12},
                           ByteSpan{ct.value().data(), ct.value().size()},
                           ByteSpan{aad.data(), aad.size()});
    EXPECT_FALSE(pt.has_value());
    EXPECT_EQ(pt.error().code, ErrorCode::AeadDecryptFailed);
}

TEST_P(AesGcmTest, Decrypt_WrongAAD_Fails) {
    AeadKey key;
    key.data.resize(aead.key_size());
    std::fill(key.data.data(), key.data.data() + key.data.size(), std::byte{0x33});
    std::array<std::byte, 12> nonce{};

    const auto plaintext = bytes_from_sv("data");
    const auto aad       = bytes_from_sv("correct-aad");

    auto ct = aead.encrypt(key, ByteSpan{nonce.data(), 12},
                           ByteSpan{plaintext.data(), plaintext.size()},
                           ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(ct.has_value());

    const auto wrong_aad = bytes_from_sv("wrong-aad");
    auto pt = aead.decrypt(key, ByteSpan{nonce.data(), 12},
                           ByteSpan{ct.value().data(), ct.value().size()},
                           ByteSpan{wrong_aad.data(), wrong_aad.size()});
    EXPECT_FALSE(pt.has_value());
    EXPECT_EQ(pt.error().code, ErrorCode::AeadDecryptFailed);
}
