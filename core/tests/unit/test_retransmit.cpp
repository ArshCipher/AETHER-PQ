// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_retransmit.cpp — Unit tests for RetransmitManager

#include "uav_pqc/transport/retransmit.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::transport;

TEST(RetransmitAckTest, RoundTripSerialisation) {
    FragmentAck ack{
        .stream_id = 42,
        .bitmap = 0b1011
    };

    Bytes ser = ack.serialise();
    auto deser_res = FragmentAck::deserialise(ByteSpan{ser.data(), ser.size()});
    ASSERT_TRUE(deser_res.has_value());

    EXPECT_EQ(deser_res.value().stream_id, ack.stream_id);
    EXPECT_EQ(deser_res.value().bitmap, ack.bitmap);
    EXPECT_TRUE(deser_res.value().has_fragment(0));
    EXPECT_TRUE(deser_res.value().has_fragment(1));
    EXPECT_FALSE(deser_res.value().has_fragment(2));
    EXPECT_TRUE(deser_res.value().has_fragment(3));
}

TEST(RetransmitManagerTest, RetransmitsMissingOnAckAndFinishes) {
    std::vector<Fragment> sent_fragments;
    auto send_fn = [&](const Fragment& f) -> VoidResult {
        sent_fragments.push_back(f);
        return ok();
    };

    RetransmitManager manager(send_fn, 1000, 3);

    Fragment f0{1, 0, 3, {std::byte{0}}};
    Fragment f1{1, 1, 3, {std::byte{1}}};
    Fragment f2{1, 2, 3, {std::byte{2}}};
    std::vector<Fragment> stream_frags = {f0, f1, f2};

    EXPECT_TRUE(manager.track_stream(1, stream_frags).has_value());

    // Send an ACK with only fragment 0 and 2 acknowledged (bitmap: 0b101 = 5)
    FragmentAck ack{1, 0b101};
    sent_fragments.clear();
    auto ack_res = manager.process_ack(ack, 1000);
    EXPECT_TRUE(ack_res.has_value());

    // Manager should have retransmitted fragment 1 (index 1)
    ASSERT_EQ(sent_fragments.size(), 1u);
    EXPECT_EQ(sent_fragments[0].fragment_index, 1);

    // Stream should not be complete yet
    EXPECT_FALSE(manager.is_complete(1));

    // Send an ACK completing the stream (bitmap: 0b111 = 7)
    FragmentAck ack_fin{1, 0b111};
    sent_fragments.clear();
    auto ack_fin_res = manager.process_ack(ack_fin, 2000);
    EXPECT_TRUE(ack_fin_res.has_value());

    // Stream should be marked as complete
    EXPECT_TRUE(manager.is_complete(1));
}

TEST(RetransmitManagerTest, RetransmitExceedsMaxRetriesFails) {
    std::vector<Fragment> sent_fragments;
    auto send_fn = [&](const Fragment& f) -> VoidResult {
        sent_fragments.push_back(f);
        return ok();
    };

    // max_retries=2, retry_ms=1000
    RetransmitManager manager(send_fn, 1000, 2);

    Fragment f0{1, 0, 2, {std::byte{0}}};
    Fragment f1{1, 1, 2, {std::byte{1}}};
    std::vector<Fragment> stream_frags = {f0, f1};

    EXPECT_TRUE(manager.track_stream(1, stream_frags).has_value());

    // Tick at t=1: sets last_sent_ms=1 (breaks the uninit==0 sentinel)
    EXPECT_TRUE(manager.tick(1).has_value());
    EXPECT_FALSE(manager.is_complete(1));

    // Tick at t=1002 (after retry_ms=1000): first timer-based retransmit
    // retry counts reach 1 for each fragment
    EXPECT_TRUE(manager.tick(1002).has_value());
    EXPECT_FALSE(manager.is_complete(1)); // still 1 retry left

    // Tick at t=2003: second timer-based retransmit
    // retry counts reach max_retries (2) for each fragment
    EXPECT_TRUE(manager.tick(2003).has_value());
    EXPECT_FALSE(manager.is_complete(1)); // sent last retransmit, not yet abandoned

    // Tick at t=3004: all fragment retry counts are now >= max_retries
    // tick() detects any_exhausted && !any_retransmitted → removes the stream
    EXPECT_TRUE(manager.tick(3004).has_value());

    // Stream should have been removed after exhausting retries
    EXPECT_TRUE(manager.is_complete(1));
}
