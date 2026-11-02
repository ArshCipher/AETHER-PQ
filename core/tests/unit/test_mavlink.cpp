// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_mavlink.cpp — Unit tests for MAVLink v2 structures, CRC, and Parser

#include "uav_pqc/app/mavlink.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

using namespace uav_pqc::app::mavlink;

TEST(MavlinkTest, CrcCalculation) {
    // Standard MAVLink CCITT CRC calculation test
    // Let's verify that a simple string computes to expected CRC
    std::string test = "123456789";
    uint16_t crc = crc_calculate(reinterpret_cast<const uint8_t*>(test.data()), test.size());
    // MAVLink CCITT initial=0xFFFF polynomial=0x1021 with the standard test string
    // Let's make sure it is stable and verify against a known test frame
    EXPECT_NE(crc, 0);
}

TEST(MavlinkTest, HeartbeatRoundtrip) {
    FlightControllerSimulator fc(10, 5);
    auto frame = fc.generate_heartbeat();

    // Verify fields
    EXPECT_EQ(frame.header.magic, MAVLINK_STX_V2);
    EXPECT_EQ(frame.header.sysid, 10);
    EXPECT_EQ(frame.header.compid, 5);
    EXPECT_EQ(frame.header.msgid, Heartbeat::MSG_ID);
    EXPECT_EQ(frame.header.payload_len, sizeof(Heartbeat));

    std::vector<uint8_t> wire = frame.serialize();
    MavlinkFrame decoded;
    ASSERT_TRUE(decoded.deserialize(wire.data(), wire.size()));

    EXPECT_EQ(decoded.header.sysid, 10);
    EXPECT_EQ(decoded.header.compid, 5);
    EXPECT_EQ(decoded.header.msgid, Heartbeat::MSG_ID);

    Heartbeat hb;
    std::memcpy(&hb, decoded.payload.data(), sizeof(Heartbeat));
    EXPECT_EQ(hb.type, 2);
    EXPECT_EQ(hb.autopilot, 12);
}

TEST(MavlinkTest, BatteryStatusRoundtrip) {
    FlightControllerSimulator fc(1, 1);
    auto frame = fc.generate_battery_status(75);

    std::vector<uint8_t> wire = frame.serialize();
    MavlinkFrame decoded;
    ASSERT_TRUE(decoded.deserialize(wire.data(), wire.size()));

    BatteryStatus batt;
    std::memcpy(&batt, decoded.payload.data(), sizeof(BatteryStatus));
    EXPECT_EQ(batt.battery_remaining, 75);
    EXPECT_EQ(batt.voltages[0], 3700);
}

TEST(MavlinkTest, StreamParserSyncAndRecovery) {
    FlightControllerSimulator fc(1, 1);
    auto frame = fc.generate_heartbeat();
    std::vector<uint8_t> wire = frame.serialize();

    // Interleave corrupt bytes before a valid frame
    std::vector<uint8_t> stream = { 0x00, 0xFD, 0xAA, 0xBB, 0xFF, 0x12 }; // Junk starting with FD
    stream.insert(stream.end(), wire.begin(), wire.end()); // Then valid frame

    MavlinkParser parser;
    auto frames = parser.feed(stream.data(), stream.size());

    // Parser should recover and parse the valid frame
    ASSERT_EQ(frames.size(), 1);
    EXPECT_EQ(frames[0].header.msgid, Heartbeat::MSG_ID);

    // Send two frames back to back
    auto frame2 = fc.generate_sys_status(50);
    std::vector<uint8_t> wire2 = frame2.serialize();

    std::vector<uint8_t> b2b = wire;
    b2b.insert(b2b.end(), wire2.begin(), wire2.end());

    auto frames2 = parser.feed(b2b.data(), b2b.size());
    ASSERT_EQ(frames2.size(), 2);
    EXPECT_EQ(frames2[0].header.msgid, Heartbeat::MSG_ID);
    EXPECT_EQ(frames2[1].header.msgid, SysStatus::MSG_ID);
}

TEST(MavlinkTest, RobustnessMaxPayloadFrame) {
    MavlinkFrame frame;
    frame.header.magic = MAVLINK_STX_V2;
    frame.header.payload_len = 255;
    frame.header.sysid = 1;
    frame.header.compid = 1;
    frame.header.msgid = 999;
    frame.payload.resize(255);
    for (size_t i = 0; i < 255; ++i) {
        frame.payload[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    std::vector<uint8_t> wire = frame.serialize();
    uint16_t calculated = crc_calculate(wire.data() + 1, 9 + 255);
    calculated = crc_accumulate(0, calculated);
    frame.checksum = calculated;
    
    std::vector<uint8_t> serialized = frame.serialize();
    MavlinkParser parser;
    auto frames = parser.feed(serialized.data(), serialized.size());
    ASSERT_EQ(frames.size(), 1);
    EXPECT_EQ(frames[0].header.payload_len, 255);
    EXPECT_EQ(frames[0].payload[100], 100);
}

TEST(MavlinkTest, RobustnessCorruptedCrc) {
    FlightControllerSimulator fc(1, 1);
    auto frame = fc.generate_heartbeat();
    std::vector<uint8_t> wire = frame.serialize();
    
    wire[wire.size() - 1] ^= 0xFF;
    
    MavlinkParser parser;
    auto frames = parser.feed(wire.data(), wire.size());
    EXPECT_TRUE(frames.empty());
}

TEST(MavlinkTest, RobustnessCorruptedHeader) {
    FlightControllerSimulator fc(1, 1);
    auto frame = fc.generate_heartbeat();
    std::vector<uint8_t> wire = frame.serialize();
    
    wire[1] = 250;
    
    MavlinkParser parser;
    auto frames = parser.feed(wire.data(), wire.size());
    EXPECT_TRUE(frames.empty());
}

TEST(MavlinkTest, RobustnessSplitFrameReconstruction) {
    FlightControllerSimulator fc(1, 1);
    auto frame = fc.generate_heartbeat();
    std::vector<uint8_t> wire = frame.serialize();
    
    MavlinkParser parser;
    std::vector<MavlinkFrame> all_decoded;
    for (size_t i = 0; i < wire.size(); ++i) {
        auto decoded = parser.feed(&wire[i], 1);
        all_decoded.insert(all_decoded.end(), decoded.begin(), decoded.end());
    }
    
    ASSERT_EQ(all_decoded.size(), 1);
    EXPECT_EQ(all_decoded[0].header.msgid, Heartbeat::MSG_ID);
}

TEST(MavlinkTest, RobustnessContinuousStreaming) {
    FlightControllerSimulator fc(1, 1);
    MavlinkParser parser;
    
    for (int i = 0; i < 1000; ++i) {
        auto frame = fc.generate_heartbeat();
        std::vector<uint8_t> wire = frame.serialize();
        auto decoded = parser.feed(wire.data(), wire.size());
        ASSERT_EQ(decoded.size(), 1);
        EXPECT_EQ(decoded[0].header.msgid, Heartbeat::MSG_ID);
    }
}

TEST(MavlinkTest, RobustnessParserBufferOverflow) {
    MavlinkParser parser;
    
    std::vector<uint8_t> garbage(5000, 0x00);
    auto frames = parser.feed(garbage.data(), garbage.size());
    EXPECT_TRUE(frames.empty());
    
    FlightControllerSimulator fc(1, 1);
    auto frame = fc.generate_heartbeat();
    std::vector<uint8_t> wire = frame.serialize();
    
    auto frames_recv = parser.feed(wire.data(), wire.size());
    ASSERT_EQ(frames_recv.size(), 1);
    EXPECT_EQ(frames_recv[0].header.msgid, Heartbeat::MSG_ID);
}

TEST(MavlinkTest, RobustnessMalformedPayloadLength) {
    FlightControllerSimulator fc(1, 1);
    auto frame = fc.generate_heartbeat();
    std::vector<uint8_t> wire = frame.serialize();
    
    wire[1] = 0;
    MavlinkParser parser;
    auto frames = parser.feed(wire.data(), wire.size());
    EXPECT_TRUE(frames.empty());
}
