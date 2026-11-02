// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file retransmit.cpp
 * @brief Selective retransmission manager implementation.
 */

#include "uav_pqc/transport/retransmit.hpp"
#include "uav_pqc/common/logging.hpp"

#include <algorithm>

namespace uav_pqc::transport {

// ── FragmentAck serialise / deserialise ───────────────────────────────────────

Bytes FragmentAck::serialise() const {
    Bytes out(10); // 2 (stream_id) + 8 (bitmap)
    out[0] = static_cast<std::byte>((stream_id >> 8) & 0xFF);
    out[1] = static_cast<std::byte>(stream_id & 0xFF);
    write_u64_be(MutableByteSpan{out.data() + 2, 8}, bitmap);
    return out;
}

Result<FragmentAck> FragmentAck::deserialise(ByteSpan data) {
    if (data.size() < 10) {
        return err<FragmentAck>(ErrorCode::InvalidArgument,
            "FragmentAck too short");
    }
    FragmentAck ack;
    ack.stream_id = (static_cast<std::uint16_t>(data[0]) << 8) |
                     static_cast<std::uint16_t>(data[1]);
    ack.bitmap    = read_u64_be(data.subspan(2, 8));
    return ok<FragmentAck>(ack);
}

// ── Constructor ───────────────────────────────────────────────────────────────

RetransmitManager::RetransmitManager(SendFragmentFn send_fn,
                                     Timestamp retry_ms,
                                     std::uint8_t max_retries,
                                     std::shared_ptr<platform::IClock> clock)
    : send_fn_(std::move(send_fn)),
      retry_ms_(retry_ms),
      max_retries_(max_retries),
      clock_(clock) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
}

// ── track_stream ──────────────────────────────────────────────────────────────

VoidResult RetransmitManager::track_stream(StreamId stream_id,
                                            std::vector<Fragment> fragments) {
    return track_stream(stream_id, std::move(fragments), nullptr);
}

VoidResult RetransmitManager::track_stream(StreamId stream_id,
                                            std::vector<Fragment> fragments,
                                            SendFragmentFn per_stream_fn) {
    StreamTrack track;
    track.stream_id   = stream_id;
    track.fragments   = std::move(fragments);
    track.ack_bitmap  = 0;
    track.fragment_retry_counts.assign(track.fragments.size(), 0);
    track.last_sent_ms = 0;
    track.send_fn     = std::move(per_stream_fn);
    streams_.push_back(std::move(track));
    return ok();
}

// ── process_ack ───────────────────────────────────────────────────────────────

VoidResult RetransmitManager::process_ack(const FragmentAck& ack, Timestamp now_ms) {
    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    for (auto& track : streams_) {
        if (track.stream_id != ack.stream_id) continue;

        track.ack_bitmap |= ack.bitmap;

        // Check if fully acknowledged
        std::uint64_t full_mask =
            (track.fragments.size() < 64)
            ? ((1ULL << track.fragments.size()) - 1)
            : UINT64_MAX;

        if ((track.ack_bitmap & full_mask) == full_mask) {
            UAV_PQC_LOG_DEBUG("transport.retransmit",
                              "Stream {} fully acknowledged", ack.stream_id);
            remove_stream(ack.stream_id);
            return ok();
        }

        // ACK-triggered fast retransmit: immediately resend missing fragments.
        // NOTE: We do NOT increment retry counts here — that is done only in
        // the timer-based tick() to prevent burning through retries when
        // multiple partial ACKs arrive in rapid succession.
        const auto& effective_fn = track.send_fn ? track.send_fn : send_fn_;
        for (std::size_t i = 0; i < track.fragments.size(); ++i) {
            if (!((track.ack_bitmap >> i) & 1)) {
                auto r = effective_fn(track.fragments[i]);
                if (!r) {
                    UAV_PQC_LOG_WARN("transport.retransmit",
                                     "ACK-triggered retransmit fragment {} failed: {}",
                                     i, r.error().message);
                }
            }
        }
        track.last_sent_ms = current_time;
        return ok();
    }
    return ok(); // unknown stream (already completed)
}

// ── tick ─────────────────────────────────────────────────────────────────────

VoidResult RetransmitManager::tick(Timestamp now_ms) {
    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    // Collect streams that exhausted retries, to remove after iteration.
    std::vector<StreamId> to_remove;

    for (auto& track : streams_) {
        if (track.last_sent_ms == 0) {
            track.last_sent_ms = current_time;
            continue;
        }
        if ((current_time - track.last_sent_ms) < retry_ms_) {
            continue;
        }

        UAV_PQC_LOG_DEBUG("transport.retransmit",
                          "Stream {} timer-triggered retransmit check",
                          track.stream_id);

        const auto& effective_fn = track.send_fn ? track.send_fn : send_fn_;
        bool any_retransmitted = false;
        bool any_exhausted = false;
        for (std::size_t i = 0; i < track.fragments.size(); ++i) {
            if (!((track.ack_bitmap >> i) & 1)) {
                if (track.fragment_retry_counts[i] >= max_retries_) {
                    UAV_PQC_LOG_ERROR("transport.retransmit",
                                     "Stream {} fragment {} timer-expired after {} retries",
                                     track.stream_id, i, track.fragment_retry_counts[i]);
                    any_exhausted = true;
                    continue;
                }
                effective_fn(track.fragments[i]);
                track.fragment_retry_counts[i]++;
                any_retransmitted = true;
            }
        }
        if (any_exhausted && !any_retransmitted) {
            // All missing fragments exhausted — give up on this stream
            to_remove.push_back(track.stream_id);
        } else if (any_retransmitted) {
            track.last_sent_ms = current_time;
        }
    }

    for (auto sid : to_remove) {
        UAV_PQC_LOG_ERROR("transport.retransmit",
                          "Stream {} abandoned after all fragments exceeded max retries ({})",
                          sid, max_retries_);
        remove_stream(sid);
    }

    return ok();
}

// ── is_complete ───────────────────────────────────────────────────────────────

bool RetransmitManager::is_complete(StreamId stream_id) const noexcept {
    for (const auto& track : streams_) {
        if (track.stream_id == stream_id) return false; // still tracking → not complete
    }
    return true; // not found → was completed and removed
}

// ── remove_stream ─────────────────────────────────────────────────────────────

void RetransmitManager::remove_stream(StreamId stream_id) {
    streams_.erase(std::remove_if(streams_.begin(), streams_.end(),
        [stream_id](const StreamTrack& t) { return t.stream_id == stream_id; }),
        streams_.end());
}

} // namespace uav_pqc::transport
