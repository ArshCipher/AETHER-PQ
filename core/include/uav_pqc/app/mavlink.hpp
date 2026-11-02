// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <vector>
#include <cstring>
#include <string>
#include <iostream>
#include <array>
#include <memory>
#include "uav_pqc/common/types.hpp"

namespace uav_pqc::app {
struct DecryptedMavlinkStream {
    Bytes data;
};
struct DecryptedVideoFrame {
    NodeId sender_id;
    Bytes data;
};
} // namespace uav_pqc::app

namespace uav_pqc::app::mavlink {

template<typename T, size_t N>
class FixedVector {
public:
    FixedVector() : size_(0) {}
    FixedVector(size_t n) : size_(n > N ? N : n) {}

    FixedVector(const FixedVector&) = default;
    FixedVector& operator=(const FixedVector&) = default;
    FixedVector(FixedVector&&) noexcept = default;
    FixedVector& operator=(FixedVector&&) noexcept = default;

    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }
    void resize(size_t n) { size_ = (n > N) ? N : n; }
    void clear() { size_ = 0; }

    T* data() { return data_; }
    const T* data() const { return data_; }

    T& operator[](size_t i) { return data_[i]; }
    const T& operator[](size_t i) const { return data_[i]; }

    T* begin() { return data_; }
    const T* begin() const { return data_; }
    T* end() { return data_ + size_; }
    const T* end() const { return data_ + size_; }

    void assign(const T* first, const T* last) {
        size_t n = static_cast<size_t>(last - first);
        size_ = (n > N) ? N : n;
        std::memcpy(data_, first, size_ * sizeof(T));
    }

    template<typename InputIt>
    void assign(InputIt first, InputIt last) {
        size_ = 0;
        while (first != last && size_ < N) {
            data_[size_++] = *first++;
        }
    }

    void push_back(const T& val) {
        if (size_ < N) {
            data_[size_++] = val;
        }
    }

    template<typename InputIt>
    void insert(const T* pos, InputIt first, InputIt last) {
        (void)pos;
        size_t n = static_cast<size_t>(last - first);
        if (size_ + n > N) {
            n = N - size_;
        }
        std::memcpy(data_ + size_, first, n * sizeof(T));
        size_ += n;
    }

    void erase(const T* first, const T* last) {
        size_t start_idx = static_cast<size_t>(first - data_);
        size_t end_idx = static_cast<size_t>(last - data_);
        if (end_idx > size_) end_idx = size_;
        if (start_idx < end_idx) {
            size_t num_to_erase = end_idx - start_idx;
            std::memmove(data_ + start_idx, data_ + end_idx, (size_ - end_idx) * sizeof(T));
            size_ -= num_to_erase;
        }
    }

private:
    T data_[N];
    size_t size_;
};

// Start byte for MAVLink v2
constexpr uint8_t MAVLINK_STX_V2 = 0xFD;

#pragma pack(push, 1)

// MAVLink v2 packet header
struct MavlinkHeader {
    uint8_t  magic;             // STX (0xFD)
    uint8_t  payload_len;       // Payload length
    uint8_t  incompat_flags;    // Incompatibility flags
    uint8_t  compat_flags;      // Compatibility flags
    uint8_t  seq;               // Sequence
    uint8_t  sysid;             // System ID
    uint8_t  compid;            // Component ID
    uint32_t msgid : 24;        // Message ID (24-bit)
};

// HEARTBEAT (ID #0)
struct Heartbeat {
    static constexpr uint32_t MSG_ID = 0;
    static constexpr uint8_t CRC_EXTRA = 50;

    uint32_t custom_mode;
    uint8_t  type;
    uint8_t  autopilot;
    uint8_t  base_mode;
    uint8_t  system_status;
    uint8_t  mavlink_version;
};

// SYS_STATUS (ID #1)
struct SysStatus {
    static constexpr uint32_t MSG_ID = 1;
    static constexpr uint8_t CRC_EXTRA = 124;

    uint32_t onboard_control_sensors_present;
    uint32_t onboard_control_sensors_enabled;
    uint32_t onboard_control_sensors_health;
    uint16_t load;
    uint16_t voltage_battery;
    int16_t  current_battery;
    uint16_t drop_rate_comm;
    uint16_t errors_comm;
    uint16_t errors_count1;
    uint16_t errors_count2;
    uint16_t errors_count3;
    uint16_t errors_count4;
    int8_t   battery_remaining;
};

// GPS_RAW_INT (ID #24)
struct GpsRawInt {
    static constexpr uint32_t MSG_ID = 24;
    static constexpr uint8_t CRC_EXTRA = 24;

    uint64_t time_usec;
    int32_t  lat;
    int32_t  lon;
    int32_t  alt;
    uint16_t eph;
    uint16_t epv;
    uint16_t vel;
    uint16_t cog;
    uint8_t  fix_type;
    uint8_t  satellites_visible;
};

// ATTITUDE (ID #30)
struct Attitude {
    static constexpr uint32_t MSG_ID = 30;
    static constexpr uint8_t CRC_EXTRA = 39;

    uint32_t time_boot_ms;
    float    roll;
    float    pitch;
    float    yaw;
    float    rollspeed;
    float    pitchspeed;
    float    yawspeed;
};

// LOCAL_POSITION_NED (ID #32)
struct LocalPositionNed {
    static constexpr uint32_t MSG_ID = 32;
    static constexpr uint8_t CRC_EXTRA = 185;

    uint32_t time_boot_ms;
    float    x;
    float    y;
    float    z;
    float    vx;
    float    vy;
    float    vz;
};

// GLOBAL_POSITION_INT (ID #33)
struct GlobalPositionInt {
    static constexpr uint32_t MSG_ID = 33;
    static constexpr uint8_t CRC_EXTRA = 104;

    uint32_t time_boot_ms;
    int32_t  lat;
    int32_t  lon;
    int32_t  alt;
    int32_t  relative_alt;
    int16_t  vx;
    int16_t  vy;
    int16_t  vz;
    uint16_t hdg;
};

// MISSION_CURRENT (ID #42)
struct MissionCurrent {
    static constexpr uint32_t MSG_ID = 42;
    static constexpr uint8_t CRC_EXTRA = 28;

    uint16_t seq;
};

// COMMAND_LONG (ID #76)
struct CommandLong {
    static constexpr uint32_t MSG_ID = 76;
    static constexpr uint8_t CRC_EXTRA = 152;

    float    param1;
    float    param2;
    float    param3;
    float    param4;
    float    param5;
    float    param6;
    float    param7;
    uint16_t command;
    uint8_t  target_system;
    uint8_t  target_component;
    uint8_t  confirmation;
};

// BATTERY_STATUS (ID #147)
struct BatteryStatus {
    static constexpr uint32_t MSG_ID = 147;
    static constexpr uint8_t CRC_EXTRA = 154;

    int32_t  current_consumed;
    int32_t  energy_consumed;
    int16_t  temperature;
    uint16_t voltages[10];
    int16_t  current_battery;
    uint8_t  id;
    uint8_t  battery_function;
    uint8_t  type;
    int8_t   battery_remaining;
};

#pragma pack(pop)

// MAVLink CRC-16 calculation helper
inline uint16_t crc_accumulate(uint8_t data, uint16_t crc) {
    uint8_t tmp = data ^ (crc & 0xFF);
    tmp ^= (tmp << 4);
    return (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4);
}

inline uint16_t crc_calculate(const uint8_t* buffer, uint16_t length) {
    uint16_t crc = 0xFFFF;
    for (uint16_t i = 0; i < length; ++i) {
        crc = crc_accumulate(buffer[i], crc);
    }
    return crc;
}

// Get standard CRC_EXTRA by message ID
inline uint8_t get_crc_extra(uint32_t msgid) {
    switch (msgid) {
        case Heartbeat::MSG_ID:         return Heartbeat::CRC_EXTRA;
        case SysStatus::MSG_ID:         return SysStatus::CRC_EXTRA;
        case GpsRawInt::MSG_ID:         return GpsRawInt::CRC_EXTRA;
        case Attitude::MSG_ID:          return Attitude::CRC_EXTRA;
        case LocalPositionNed::MSG_ID:  return LocalPositionNed::CRC_EXTRA;
        case GlobalPositionInt::MSG_ID: return GlobalPositionInt::CRC_EXTRA;
        case MissionCurrent::MSG_ID:    return MissionCurrent::CRC_EXTRA;
        case CommandLong::MSG_ID:       return CommandLong::CRC_EXTRA;
        case BatteryStatus::MSG_ID:     return BatteryStatus::CRC_EXTRA;
        default:                        return 0;
    }
}

// MAVLink Frame Class
struct MavlinkFrame {
    MavlinkHeader header;
    FixedVector<uint8_t, 260> payload;
    uint16_t checksum = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(10 + payload.size() + 2);
        // Header
        std::memcpy(data.data(), &header, 10);
        // Payload
        if (!payload.empty()) {
            std::memcpy(data.data() + 10, payload.data(), payload.size());
        }
        // Checksum
        std::memcpy(data.data() + 10 + payload.size(), &checksum, 2);
        return data;
    }

    bool deserialize(const uint8_t* buffer, size_t size) {
        if (size < 12) return false; // Min size of v2 frame (10 header + 2 checksum)
        if (buffer[0] != MAVLINK_STX_V2) return false;

        std::memcpy(&header, buffer, 10);
        if (size < 12 + header.payload_len) return false;

        payload.resize(header.payload_len);
        if (header.payload_len > 0) {
            std::memcpy(payload.data(), buffer + 10, header.payload_len);
        }
        std::memcpy(&checksum, buffer + 10 + header.payload_len, 2);

        // Verify checksum
        uint16_t calculated = crc_calculate(buffer + 1, 9 + header.payload_len);
        calculated = crc_accumulate(get_crc_extra(header.msgid), calculated);

        return calculated == checksum;
    }

    template<typename T>
    static MavlinkFrame pack(const T& msg, uint8_t seq, uint8_t sysid, uint8_t compid) {
        MavlinkFrame frame;
        frame.header.magic = MAVLINK_STX_V2;
        frame.header.payload_len = sizeof(T);
        frame.header.incompat_flags = 0;
        frame.header.compat_flags = 0;
        frame.header.seq = seq;
        frame.header.sysid = sysid;
        frame.header.compid = compid;
        frame.header.msgid = T::MSG_ID;

        frame.payload.resize(sizeof(T));
        std::memcpy(frame.payload.data(), &msg, sizeof(T));

        // Compute checksum
        std::vector<uint8_t> wire = frame.serialize();
        uint16_t calculated = crc_calculate(wire.data() + 1, 9 + sizeof(T));
        calculated = crc_accumulate(T::CRC_EXTRA, calculated);
        frame.checksum = calculated;

        return frame;
    }
};

// Simulated Flight Controller (PX4/ArduPilot abstract model)
class FlightControllerSimulator {
public:
    FlightControllerSimulator(uint8_t sysid = 1, uint8_t compid = 1)
        : sysid_(sysid), compid_(compid), seq_(0), boot_time_(0) {}

    MavlinkFrame generate_heartbeat() {
        Heartbeat hb{
            .custom_mode = 0,
            .type = 2,              // MAV_TYPE_QUADROTOR
            .autopilot = 12,        // MAV_AUTOPILOT_PX4
            .base_mode = 81,        // MAV_MODE_FLAG_SAFETY_ARMED | MAV_MODE_FLAG_STABILIZE_ENABLED
            .system_status = 4,     // MAV_STATE_ACTIVE
            .mavlink_version = 3
        };
        return MavlinkFrame::pack(hb, seq_++, sysid_, compid_);
    }

    MavlinkFrame generate_sys_status(int8_t battery_remaining = 98) {
        SysStatus status{
            .onboard_control_sensors_present = 0x000F,
            .onboard_control_sensors_enabled = 0x000F,
            .onboard_control_sensors_health = 0x000F,
            .load = 250, // 25% CPU
            .voltage_battery = 11100, // 11.1V
            .current_battery = 500, // 5A
            .drop_rate_comm = 0,
            .errors_comm = 0,
            .errors_count1 = 0,
            .errors_count2 = 0,
            .errors_count3 = 0,
            .errors_count4 = 0,
            .battery_remaining = battery_remaining
        };
        return MavlinkFrame::pack(status, seq_++, sysid_, compid_);
    }

    MavlinkFrame generate_gps_raw_int(int32_t lat = 473714870, int32_t lon = 85406080, int32_t alt = 450000) {
        GpsRawInt gps{
            .time_usec = static_cast<uint64_t>(boot_time_) * 1000,
            .lat = lat,
            .lon = lon,
            .alt = alt,
            .eph = 100,
            .epv = 150,
            .vel = 1200, // 12 m/s
            .cog = 4500, // 45 deg
            .fix_type = 3, // 3D fix
            .satellites_visible = 12
        };
        return MavlinkFrame::pack(gps, seq_++, sysid_, compid_);
    }

    MavlinkFrame generate_attitude() {
        Attitude att{
            .time_boot_ms = boot_time_,
            .roll = 0.05f,
            .pitch = 0.02f,
            .yaw = 0.78f,
            .rollspeed = 0.001f,
            .pitchspeed = 0.002f,
            .yawspeed = 0.01f
        };
        return MavlinkFrame::pack(att, seq_++, sysid_, compid_);
    }

    MavlinkFrame generate_local_position_ned(float x = 10.0f, float y = 20.0f, float z = -50.0f) {
        LocalPositionNed pos{
            .time_boot_ms = boot_time_,
            .x = x,
            .y = y,
            .z = z,
            .vx = 5.0f,
            .vy = 2.0f,
            .vz = 0.1f
        };
        return MavlinkFrame::pack(pos, seq_++, sysid_, compid_);
    }

    MavlinkFrame generate_global_position_int(int32_t lat = 473714870, int32_t lon = 85406080, int32_t alt = 450000) {
        GlobalPositionInt pos{
            .time_boot_ms = boot_time_,
            .lat = lat,
            .lon = lon,
            .alt = alt,
            .relative_alt = 120000, // 120 m
            .vx = 500, // 5 m/s
            .vy = 200,
            .vz = 10,
            .hdg = 4500
        };
        return MavlinkFrame::pack(pos, seq_++, sysid_, compid_);
    }

    MavlinkFrame generate_mission_current(uint16_t seq = 2) {
        MissionCurrent mission{
            .seq = seq
        };
        return MavlinkFrame::pack(mission, seq_++, sysid_, compid_);
    }

    MavlinkFrame generate_battery_status(int8_t remaining = 98) {
        BatteryStatus batt{
            .current_consumed = 1500, // mAh
            .energy_consumed = -1,
            .temperature = 2800, // 28 degC
            .voltages = {3700, 3700, 3700, 0, 0, 0, 0, 0, 0, 0},
            .current_battery = 500, // 5A
            .id = 0,
            .battery_function = 1, // All-systems
            .type = 2, // LiPo
            .battery_remaining = remaining
        };
        return MavlinkFrame::pack(batt, seq_++, sysid_, compid_);
    }

    void update_time(uint32_t dt_ms) {
        boot_time_ += dt_ms;
    }

private:
    uint8_t  sysid_;
    uint8_t  compid_;
    uint8_t  seq_;
    uint32_t boot_time_;
};

/**
 * @brief MAVLink stream parser using a fixed-capacity sliding linear buffer.
 * 
 * DESIGN:
 * This parser stores received stream bytes in a preallocated FixedVector buffer.
 * It operates as a sliding linear buffer:
 * 1. Before appending new bytes, if the incoming chunk would cause an overflow,
 *    the oldest bytes are dropped from the front to make room.
 * 2. It scans for the start byte (STX) of a MAVLink frame.
 * 3. Once a frame is successfully deserialized, it is removed from the buffer,
 *    and the buffer shifts remaining bytes to the front.
 * 4. After each parse run, any confirmed preceding junk bytes are immediately
 *    erased from the front of the buffer, keeping the buffer size minimal.
 * This guarantees zero dynamic heap allocations and deterministic recovery from sync errors.
 */
class MavlinkParser {
public:
    MavlinkParser() = default;

    // Feeds bytes to the parser, returning a vector of successfully decoded frames
    std::vector<MavlinkFrame> feed(const uint8_t* data, size_t size) {
        // ── Pre-Insert Sliding Overflow Cleanup ──
        if (size > 4096) {
            // Incoming chunk exceeds total capacity, keep only the latest 4096 bytes
            data += (size - 4096);
            size = 4096;
        }
        if (buffer_.size() + size > 4096) {
            size_t overflow = (buffer_.size() + size) - 4096;
            std::cout << "[MavlinkParser] Buffer overflow warning: dropping " << overflow << " bytes of old data" << std::endl;
            buffer_.erase(buffer_.begin(), buffer_.begin() + overflow);
        }

        // Append new bytes to our internal buffer
        buffer_.insert(buffer_.end(), data, data + size);

        std::vector<MavlinkFrame> decoded_frames;
        decoded_frames.reserve(16);
        size_t idx = 0;

        while (idx < buffer_.size()) {
            // Find the first STX
            if (buffer_[idx] != MAVLINK_STX_V2) {
                idx++;
                continue;
            }

            // We found a potential STX at idx. Do we have enough bytes for header?
            if (idx + 10 > buffer_.size()) {
                // Not enough bytes yet, wait for more
                break;
            }

            uint8_t payload_len = buffer_[idx + 1];
            size_t frame_size = 10 + payload_len + 2;

            // If the specified frame size is impossible for MAVLink v2 (> 267 bytes), skip
            if (frame_size > 267) {
                idx++;
                continue;
            }

            if (idx + frame_size > buffer_.size()) {
                // The frame is incomplete. But wait, is there another STX downstream?
                // If there is another STX downstream, and it points to a valid complete frame,
                // then this incomplete frame must be false sync/junk!
                bool found_valid_downstream = false;
                for (size_t next_idx = idx + 1; next_idx + 10 <= buffer_.size(); ++next_idx) {
                    if (buffer_[next_idx] == MAVLINK_STX_V2) {
                        uint8_t next_len = buffer_[next_idx + 1];
                        size_t next_frame_size = 10 + next_len + 2;
                        if (next_idx + next_frame_size <= buffer_.size()) {
                            MavlinkFrame test_frame;
                            if (test_frame.deserialize(buffer_.data() + next_idx, next_frame_size)) {
                                found_valid_downstream = true;
                                break;
                            }
                        }
                    }
                }

                if (found_valid_downstream) {
                    // Skip this false sync and let the loop find the valid downstream frame
                    idx++;
                    continue;
                }

                // Otherwise, wait for more bytes
                break;
            }

            // We have the full frame candidate bytes. Try to deserialize it.
            MavlinkFrame frame;
            if (frame.deserialize(buffer_.data() + idx, frame_size)) {
                // Success!
                decoded_frames.push_back(frame);
                // Remove everything up to the end of this frame from buffer_
                buffer_.erase(buffer_.begin(), buffer_.begin() + idx + frame_size);
                idx = 0; // Restart search from the beginning of the remaining buffer
            } else {
                // Failed checksum or invalid header!
                // Skip the false STX byte and continue searching
                idx++;
            }
        }

        // ── Post-Parse Junk Discarding ──
        if (idx > 0) {
            buffer_.erase(buffer_.begin(), buffer_.begin() + idx);
        }

        return decoded_frames;
    }

private:
    FixedVector<uint8_t, 4096> buffer_;
};

} // namespace uav_pqc::app::mavlink
