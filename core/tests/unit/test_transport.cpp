// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include <gtest/gtest.h>
#include "uav_pqc/transport/transport.hpp"
#include <chrono>
#include <thread>
#include <atomic>

using namespace uav_pqc;
using namespace uav_pqc::transport;

class TransportTest : public ::testing::Test {};

TEST_F(TransportTest, LocalProcessTransportExchange) {
    NodeId id1{std::byte{0x01}};
    NodeId id2{std::byte{0x02}};

    LocalProcessTransport t1(id1);
    LocalProcessTransport t2(id2);

    ASSERT_TRUE(t1.connect("127.0.0.1:8001").has_value());
    ASSERT_TRUE(t2.connect("127.0.0.1:8002").has_value());

    std::atomic<bool> received{false};
    Bytes received_payload;
    NodeId received_sender{};

    t2.set_receive_handler([&](const NodeId& sender, Bytes data) {
        received_sender = sender;
        received_payload = std::move(data);
        received = true;
    });

    Bytes test_msg = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
    auto send_r = t1.send(id2, test_msg);
    ASSERT_TRUE(send_r.has_value());

    // Wait for async delivery (up to 500ms)
    for (int i = 0; i < 50; ++i) {
        if (received) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(received);
    EXPECT_EQ(received_sender, id1);
    EXPECT_EQ(received_payload, test_msg);

    (void)t1.disconnect();
    (void)t2.disconnect();
}

TEST_F(TransportTest, LocalProcessTransportMulticastAndBroadcast) {
    NodeId id1{std::byte{0x01}};
    NodeId id2{std::byte{0x02}};
    NodeId id3{std::byte{0x03}};

    LocalProcessTransport t1(id1);
    LocalProcessTransport t2(id2);
    LocalProcessTransport t3(id3);

    (void)t1.connect("127.0.0.1:8001");
    (void)t2.connect("127.0.0.1:8002");
    (void)t3.connect("127.0.0.1:8003");

    std::atomic<int> received_count{0};
    t2.set_receive_handler([&](const NodeId&, Bytes) { received_count++; });
    t3.set_receive_handler([&](const NodeId&, Bytes) { received_count++; });

    Bytes payload = {std::byte{0xDE}, std::byte{0xAD}};
    (void)t1.broadcast(payload);

    for (int i = 0; i < 50; ++i) {
        if (received_count == 2) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_EQ(received_count.load(), 2);

    received_count = 0;
    (void)t1.multicast({id2}, payload);

    for (int i = 0; i < 50; ++i) {
        if (received_count == 1) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_EQ(received_count.load(), 1);
}

#ifndef _WIN32
TEST_F(TransportTest, LinuxSocketTransportExchange) {
    NodeId id1{std::byte{0x01}};
    NodeId id2{std::byte{0x02}};

    LinuxSocketTransport t1;
    LinuxSocketTransport t2;

    t1.add_route(id2, "127.0.0.1", 28002);
    t2.add_route(id1, "127.0.0.1", 28001);

    ASSERT_TRUE(t1.connect("127.0.0.1:28001").has_value());
    ASSERT_TRUE(t2.connect("127.0.0.1:28002").has_value());

    std::atomic<bool> received{false};
    Bytes received_payload;
    NodeId received_sender{};

    t2.set_receive_handler([&](const NodeId& sender, Bytes data) {
        received_sender = sender;
        received_payload = std::move(data);
        received = true;
    });

    Bytes test_msg = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}};
    auto send_r = t1.send(id2, test_msg);
    ASSERT_TRUE(send_r.has_value());

    for (int i = 0; i < 50; ++i) {
        if (received) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(received);
    EXPECT_EQ(received_sender, id1);
    EXPECT_EQ(received_payload, test_msg);

    (void)t1.disconnect();
    (void)t2.disconnect();
}
#endif

TEST_F(TransportTest, Ns3TransportBasicAPI) {
    Ns3Transport transport;
    EXPECT_FALSE(transport.is_connected());
    EXPECT_TRUE(transport.connect("ns3-address").has_value());
    EXPECT_TRUE(transport.is_connected());
    EXPECT_TRUE(transport.disconnect().has_value());
    EXPECT_FALSE(transport.is_connected());
}
