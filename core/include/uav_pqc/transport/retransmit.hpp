// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file retransmit.hpp
 * @brief Selective retransmission manager for application-layer fragments.
 *
 * When fragments are lost on a lossy RF D2D link, the receiver requests
 * selective retransmission of only the missing fragments rather than
 * aborting the entire ML-KEM/ML-DSA key establishment operation.
 *
 * Protocol:
 *  1. Sender transmits all fragments and sets a per-stream retransmit timer.
 *  2. Receiver sends a FragmentAck with a bitmap of received fragments.
 *  3. Sender retransmits only the missing fragments (up to max_retries).
 *  4. After max_retries exhausted, the sender sends an Alert and resets.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/transport/fragment.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <cstdint>
#include <functional>
#include <vector>
#include <memory>

namespace uav_pqc::transport {

/**
 * @brief FragmentAck — acknowledgement of received fragments.
 *
 * bitmap is a bitmask of received fragment indices.  Bit i is set if
 * fragment[i] was successfully received.
 */
struct FragmentAck {
    StreamId     stream_id;
    std::uint64_t bitmap;      ///< Up to 64 fragments per stream (sufficient for PQC payloads)

    [[nodiscard]] bool has_fragment(std::uint8_t idx) const noexcept {
        return (bitmap >> idx) & 1u;
    }

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<FragmentAck> deserialise(ByteSpan data);
};

/**
 * @brief Per-stream retransmission state maintained by the sender.
 */
class RetransmitManager {
public:
    /**
     * @param send_fn      Callback to retransmit a fragment on demand.
     * @param retry_ms     Retransmit interval in milliseconds (default: 2000).
     * @param max_retries  Maximum retransmission attempts before giving up.
     */
    using SendFragmentFn = std::function<VoidResult(const Fragment& fragment)>;

    explicit RetransmitManager(SendFragmentFn send_fn,
                               Timestamp      retry_ms    = 2000,
                               std::uint8_t   max_retries = 20,
                               std::shared_ptr<platform::IClock> clock = nullptr);

    /**
     * @brief Register a stream with a per-destination send function.
     *
     * Used by send_message_to() to enable destination-aware retransmission.
     * @param stream_id   Stream to track.
     * @param fragments   Fragments to retransmit if missing.
     * @param send_fn     Destination-specific send callback (overrides default).
     */
    VoidResult track_stream(StreamId stream_id, std::vector<Fragment> fragments,
                            SendFragmentFn send_fn);
    ~RetransmitManager() = default;

    RetransmitManager(const RetransmitManager&)            = delete;
    RetransmitManager& operator=(const RetransmitManager&) = delete;
    RetransmitManager(RetransmitManager&&) noexcept        = default;
    RetransmitManager& operator=(RetransmitManager&&) noexcept = default;

    /**
     * @brief Register a set of sent fragments for retransmission tracking.
     */
    VoidResult track_stream(StreamId stream_id, std::vector<Fragment> fragments);

    /**
     * @brief Process an incoming ACK and retransmit missing fragments.
     *
     * @param ack     Received acknowledgement.
     * @param now_ms  Current monotonic timestamp.
     * @return        Ok if all fragments are now acknowledged, or if retransmitted.
     *                ErrorCode::TransportError if max_retries exhausted.
     */
    [[nodiscard]] VoidResult process_ack(const FragmentAck& ack, Timestamp now_ms = 0);

    /**
     * @brief Trigger timer-based retransmission check.
     *
     * Should be called every retry_ms milliseconds by the event loop.
     * Retransmits fragments for all streams that have not received an ACK.
     */
    [[nodiscard]] VoidResult tick(Timestamp now_ms = 0);

    /// Returns true if the stream has been fully acknowledged.
    [[nodiscard]] bool is_complete(StreamId stream_id) const noexcept;

    /// Remove a completed or timed-out stream from tracking.
    void remove_stream(StreamId stream_id);

private:
    struct StreamTrack {
        StreamId              stream_id;
        std::vector<Fragment> fragments;
        std::uint64_t         ack_bitmap = 0;
        std::vector<std::uint8_t> fragment_retry_counts;
        Timestamp             last_sent_ms = 0;
        /// Optional per-stream send function (set when destination is known).
        SendFragmentFn        send_fn;    ///< nullptr → use RetransmitManager::send_fn_
    };

    SendFragmentFn           send_fn_;
    Timestamp                retry_ms_;
    std::uint8_t             max_retries_;
    std::vector<StreamTrack> streams_;
    std::shared_ptr<platform::IClock> clock_;
};

} // namespace uav_pqc::transport
