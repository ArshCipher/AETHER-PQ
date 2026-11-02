// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_hkdf.cpp — Unit tests for HKDF

#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/common/types.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::crypto;

TEST(HkdfTest, Sha256_Derive_ProducesCorrectLength) {
    Hkdf hkdf(HkdfHash::Sha256);
    const auto ikm  = bytes_from_sv("input key material");
    const auto info = bytes_from_sv("test info");

    auto result = hkdf.derive({}, ByteSpan{ikm.data(), ikm.size()},
                               ByteSpan{info.data(), info.size()}, 32);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result.value().size(), 32u);
}

TEST(HkdfTest, DifferentInfo_DifferentOutput) {
    Hkdf hkdf(HkdfHash::Sha256);
    const auto ikm   = bytes_from_sv("same ikm");
    const auto info1 = bytes_from_sv("label-one");
    const auto info2 = bytes_from_sv("label-two");

    auto r1 = hkdf.derive({}, ByteSpan{ikm.data(), ikm.size()},
                           ByteSpan{info1.data(), info1.size()}, 32);
    auto r2 = hkdf.derive({}, ByteSpan{ikm.data(), ikm.size()},
                           ByteSpan{info2.data(), info2.size()}, 32);
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r2.has_value());

    EXPECT_NE(
        std::vector<std::byte>(r1.value().data(), r1.value().data() + 32),
        std::vector<std::byte>(r2.value().data(), r2.value().data() + 32));
}

TEST(HkdfTest, ExtractExpand_ConsistentWithDerived) {
    Hkdf hkdf(HkdfHash::Sha256);
    const auto salt = bytes_from_sv("salt");
    const auto ikm  = bytes_from_sv("ikm");
    const auto info = bytes_from_sv("context");

    auto prk = hkdf.extract(ByteSpan{salt.data(), salt.size()},
                             ByteSpan{ikm.data(), ikm.size()});
    ASSERT_TRUE(prk.has_value());
    EXPECT_EQ(prk.value().size(), 32u);

    auto okm = hkdf.expand(prk.value().span(),
                           ByteSpan{info.data(), info.size()}, 32);
    ASSERT_TRUE(okm.has_value());
    EXPECT_EQ(okm.value().size(), 32u);

    auto combined = hkdf.derive(ByteSpan{salt.data(), salt.size()},
                                ByteSpan{ikm.data(), ikm.size()},
                                ByteSpan{info.data(), info.size()}, 32);
    ASSERT_TRUE(combined.has_value());

    EXPECT_EQ(
        std::vector<std::byte>(okm.value().data(), okm.value().data() + 32),
        std::vector<std::byte>(combined.value().data(), combined.value().data() + 32));
}

TEST(HkdfTest, Sha512_ProducesCorrectLength) {
    Hkdf hkdf(HkdfHash::Sha512);
    EXPECT_EQ(hkdf.hash_output_size(), 64u);
    const auto ikm = bytes_from_sv("key material");
    auto out = hkdf.derive({}, ByteSpan{ikm.data(), ikm.size()}, {}, 64);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out.value().size(), 64u);
}
