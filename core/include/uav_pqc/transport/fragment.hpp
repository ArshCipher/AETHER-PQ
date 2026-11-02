// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file fragment.hpp
 * @brief Application-layer fragmentation and reassembly for PQC payloads.
 *
 * PQC public keys and signatures are significantly larger than classical ones:
 *   ML-KEM-768 public key : 1184 bytes
 *   ML-DSA-65 signature   : 3309 bytes
 *
 * On lossy D2D links with typical MTUs of 500–1500 bytes, these payloads
 * require multi-fragment transmission.  This layer performs:
 *  - MTU-aware fragmentation of outbound messages
 *  - Tracking and reassembly of inbound fragment streams
 *  - Per-stream reassembly buffers with timeout-based cleanup
 *
 * Wire format per fragment:
 *   [0..1]  : stream_id (uint16, identifies the original message)
 *   [2]     : fragment_index (uint8, 0-based)
 *   [3]     : total_fragments (uint8)
 *   [4..n]  : payload slice
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace uav_pqc::transport {

/// Per-stream 2-byte identifier (wraps at 65535).
using StreamId = std::uint16_t;

/**
 * @brief A single application-layer fragment.
 */
struct Fragment {
    StreamId     stream_id;
    std::uint8_t fragment_index;
    std::uint8_t total_fragments;
    Bytes        payload;

    static constexpr std::size_t kHeaderSize = 4; // bytes

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<Fragment> deserialise(ByteSpan data);
};

/**
 * @brief Fragmentation engine for outbound large messages.
 *
 * Splits a single Bytes buffer into N Fragment objects each fitting within
 * the channel MTU.
 *
 * @param message    Complete message to fragment.
 * @param mtu        Maximum bytes per fragment (including Fragment header).
 * @param stream_id  Identifier for this message stream.
 * @return           Ordered list of Fragment objects ready to send.
 */
[[nodiscard]] Result<std::vector<Fragment>>
fragment_message(ByteSpan message, std::size_t mtu, StreamId stream_id);

/**
 * @brief Reassembly state for a single inbound message stream.
 */
class FragmentReassembler {
public:
    /**
     * @param timeout_ms  Maximum time to wait for all fragments (ms).
     *                    When exceeded, the partial buffer is discarded.
     */
    explicit FragmentReassembler(Timestamp timeout_ms = 15000);
    ~FragmentReassembler() = default;

    FragmentReassembler(const FragmentReassembler&)            = delete;
    FragmentReassembler& operator=(const FragmentReassembler&) = delete;
    FragmentReassembler(FragmentReassembler&&) noexcept        = default;
    FragmentReassembler& operator=(FragmentReassembler&&) noexcept = default;

    /**
     * @brief Feed a received fragment into the reassembler.
     *
     * @param fragment   Received fragment.
     * @param now_ms     Current monotonic timestamp.
     * @return           Completed message bytes if all fragments are present,
     *                   std::nullopt if still waiting for more fragments,
     *                   or ErrorCode::ReassemblyFailed on corruption.
     */
    [[nodiscard]] Result<std::optional<Bytes>>
    feed(const Fragment& fragment, Timestamp now_ms);

    /**
     * @brief Remove all streams that have exceeded their timeout.
     * @return Number of streams discarded.
     */
    std::size_t prune_expired(Timestamp now_ms);

    [[nodiscard]] bool is_complete() const noexcept { return complete_; }
    [[nodiscard]] std::size_t pending_streams() const noexcept;

private:
    struct StreamState {
        StreamId             stream_id;
        std::uint8_t         total_fragments = 0;
        std::vector<Bytes>   received;          ///< indexed by fragment_index
        std::size_t          received_count = 0;
        Timestamp            first_received_ms = 0;
    };

    std::vector<StreamState> streams_;
    Timestamp                timeout_ms_;
    bool                     complete_ = false;
};

} // namespace uav_pqc::transport
