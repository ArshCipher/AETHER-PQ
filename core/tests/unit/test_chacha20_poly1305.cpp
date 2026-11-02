// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_chacha20_poly1305.cpp — Unit tests for ChaCha20-Poly1305

#include "uav_pqc/crypto/chacha20_poly1305.hpp"
#include "uav_pqc/common/types.hpp"
#include <gtest/gtest.h>
#include <array>

using namespace uav_pqc;
using namespace uav_pqc::crypto;

struct ChaCha20Test : ::testing::Test {
    ChaCha20Poly1305 aead;
};

TEST_F(ChaCha20Test, Metadata) {
    EXPECT_EQ(aead.key_size(),   32u);
    EXPECT_EQ(aead.nonce_size(), 12u);
    EXPECT_EQ(aead.tag_size(),   16u);
    EXPECT_FALSE(aead.algorithm_id().empty());
}

TEST_F(ChaCha20Test, EncryptDecrypt_RoundTrip) {
    AeadKey key;
    key.data.resize(32);
    std::fill(key.data.data(), key.data.data() + key.data.size(), std::byte{0xAB});

    std::array<std::byte, 12> nonce{};
    nonce[0] = std::byte{0x01};

    const auto pt  = bytes_from_sv("post-quantum secure message");
    const auto aad = bytes_from_sv("auth-data");

    auto ct = aead.encrypt(key, ByteSpan{nonce.data(), 12},
                           ByteSpan{pt.data(), pt.size()},
                           ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(ct.has_value()) << ct.error().message;
    EXPECT_EQ(ct.value().size(), pt.size() + 16u);

    auto recovered = aead.decrypt(key, ByteSpan{nonce.data(), 12},
                                   ByteSpan{ct.value().data(), ct.value().size()},
                                   ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered.value(), pt);
}

TEST_F(ChaCha20Test, TagMismatch_Fails) {
    AeadKey key;
    key.data.resize(32);
    std::fill(key.data.data(), key.data.data() + key.data.size(), std::byte{0xFF});
    std::array<std::byte, 12> nonce{};

    const auto pt  = bytes_from_sv("msg");
    const auto aad = bytes_from_sv("aad");

    auto ct = aead.encrypt(key, ByteSpan{nonce.data(), 12},
                           ByteSpan{pt.data(), pt.size()},
                           ByteSpan{aad.data(), aad.size()});
    ASSERT_TRUE(ct.has_value());

    ct.value()[0] = ~ct.value()[0]; // flip ciphertext byte

    auto result = aead.decrypt(key, ByteSpan{nonce.data(), 12},
                               ByteSpan{ct.value().data(), ct.value().size()},
                               ByteSpan{aad.data(), aad.size()});
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::AeadDecryptFailed);
}
