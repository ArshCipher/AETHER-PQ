// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_types.cpp — Unit tests for common types and utility functions

#include "uav_pqc/common/types.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;

TEST(HexTest, to_hex_EmptySpan) {
    Bytes empty;
    EXPECT_EQ(to_hex(ByteSpan{empty.data(), empty.size()}), "");
}

TEST(HexTest, to_hex_SingleByte) {
    const Bytes buf = {std::byte{0xAB}};
    EXPECT_EQ(to_hex(ByteSpan{buf.data(), buf.size()}), "ab");
}

TEST(HexTest, to_hex_MultiBytes) {
    const Bytes buf = {std::byte{0x01}, std::byte{0x23}, std::byte{0xFF}};
    EXPECT_EQ(to_hex(ByteSpan{buf.data(), buf.size()}), "0123ff");
}

TEST(HexTest, from_hex_RoundTrip) {
    const Bytes original = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    const auto  hex      = to_hex(ByteSpan{original.data(), original.size()});
    const auto  decoded  = from_hex(hex);
    EXPECT_EQ(decoded, original);
}

TEST(HexTest, from_hex_InvalidReturnsEmpty) {
    const auto r = from_hex("ZZ"); // invalid hex
    EXPECT_TRUE(r.empty());
}

TEST(ConstantTimeTest, EqualBuffers_ReturnsTrue) {
    const Bytes a = {std::byte{0x01}, std::byte{0x02}};
    const Bytes b = {std::byte{0x01}, std::byte{0x02}};
    EXPECT_TRUE(constant_time_equal(ByteSpan{a.data(), a.size()},
                                    ByteSpan{b.data(), b.size()}));
}

TEST(ConstantTimeTest, UnequalBuffers_ReturnsFalse) {
    const Bytes a = {std::byte{0x01}, std::byte{0x02}};
    const Bytes b = {std::byte{0x01}, std::byte{0x03}};
    EXPECT_FALSE(constant_time_equal(ByteSpan{a.data(), a.size()},
                                     ByteSpan{b.data(), b.size()}));
}

TEST(ConstantTimeTest, DifferentSizes_ReturnsFalse) {
    const Bytes a = {std::byte{0x01}};
    const Bytes b = {std::byte{0x01}, std::byte{0x02}};
    EXPECT_FALSE(constant_time_equal(ByteSpan{a.data(), a.size()},
                                     ByteSpan{b.data(), b.size()}));
}

TEST(SecureBytesTest, ZeroedOnDestruction) {
    SecureBytes sb(8);
    auto* ptr = sb.data();
    // Fill with non-zero
    for (std::size_t i = 0; i < sb.size(); ++i) {
        ptr[i] = std::byte{0xFF};
    }
    sb.erase(); // explicitly zero the memory
    for (std::size_t i = 0; i < 8; ++i) {
        EXPECT_EQ(ptr[i], std::byte{0});
    }
}

TEST(U64BeTest, WriteReadRoundTrip) {
    std::array<std::byte, 8> buf{};
    write_u64_be(MutableByteSpan{buf.data(), 8}, 0xDEADBEEFCAFEBABEULL);
    const std::uint64_t result = read_u64_be(ByteSpan{buf.data(), 8});
    EXPECT_EQ(result, 0xDEADBEEFCAFEBABEULL);
}
