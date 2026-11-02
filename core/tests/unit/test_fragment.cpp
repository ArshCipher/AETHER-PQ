// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_fragment.cpp — Unit tests for fragment/reassembly

#include "uav_pqc/transport/fragment.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::transport;

TEST(FragmentTest, SmallMessage_SingleFragment) {
    const auto msg = bytes_from_sv("hello");
    auto frags = fragment_message(ByteSpan{msg.data(), msg.size()}, 1024, 1);
    ASSERT_TRUE(frags.has_value());
    ASSERT_EQ(frags.value().size(), 1u);
    EXPECT_EQ(frags.value()[0].total_fragments, 1);
    EXPECT_EQ(frags.value()[0].fragment_index, 0);
}

TEST(FragmentTest, LargeMessage_MultipleFragments) {
    Bytes big_msg(1000, std::byte{0x42});
    const std::size_t mtu = 100;
    auto frags = fragment_message(ByteSpan{big_msg.data(), big_msg.size()}, mtu, 2);
    ASSERT_TRUE(frags.has_value());
    EXPECT_GT(frags.value().size(), 1u);

    // All fragments have the same stream_id and total_fragments
    const std::uint8_t total = frags.value()[0].total_fragments;
    for (const auto& f : frags.value()) {
        EXPECT_EQ(f.stream_id, 2);
        EXPECT_EQ(f.total_fragments, total);
    }
}

TEST(FragmentTest, Serialise_Deserialise_RoundTrip) {
    Fragment f;
    f.stream_id       = 0xABCD;
    f.fragment_index  = 3;
    f.total_fragments = 7;
    f.payload         = bytes_from_sv("data payload");

    const auto bytes = f.serialise();
    auto recovered   = Fragment::deserialise(ByteSpan{bytes.data(), bytes.size()});
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered.value().stream_id,       f.stream_id);
    EXPECT_EQ(recovered.value().fragment_index,  f.fragment_index);
    EXPECT_EQ(recovered.value().total_fragments, f.total_fragments);
    EXPECT_EQ(recovered.value().payload,         f.payload);
}

TEST(ReassemblerTest, AllFragments_ReassemblesCorrectly) {
    const auto orig = bytes_from_sv("reassembled original message content");
    auto frags = fragment_message(ByteSpan{orig.data(), orig.size()}, 20, 10);
    ASSERT_TRUE(frags.has_value());

    FragmentReassembler reassembler(5000);
    std::optional<Bytes> result;

    for (const auto& f : frags.value()) {
        auto r = reassembler.feed(f, 1000);
        ASSERT_TRUE(r.has_value());
        if (r.value().has_value()) {
            result = std::move(*r.value());
        }
    }

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, orig);
}

TEST(ReassemblerTest, PartialFragments_ReturnsNullopt) {
    const auto msg = bytes_from_sv("partial message test data");
    auto frags = fragment_message(ByteSpan{msg.data(), msg.size()}, 10, 20);
    ASSERT_TRUE(frags.has_value());
    ASSERT_GT(frags.value().size(), 1u);

    FragmentReassembler reassembler(5000);
    // Feed only first fragment
    auto r = reassembler.feed(frags.value()[0], 1000);
    ASSERT_TRUE(r.has_value());
    EXPECT_FALSE(r.value().has_value());
}
