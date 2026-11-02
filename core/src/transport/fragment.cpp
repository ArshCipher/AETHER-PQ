// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file fragment.cpp
 * @brief Application-layer fragmentation and reassembly.
 */

#include "uav_pqc/transport/fragment.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <algorithm>
#include <stdexcept>

namespace uav_pqc::transport {

// ── Fragment serialise / deserialise ──────────────────────────────────────────

Bytes Fragment::serialise() const {
    Bytes out;
    out.reserve(kHeaderSize + payload.size());
    // stream_id big-endian uint16
    out.push_back(static_cast<std::byte>((stream_id >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(stream_id & 0xFF));
    out.push_back(static_cast<std::byte>(fragment_index));
    out.push_back(static_cast<std::byte>(total_fragments));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

Result<Fragment> Fragment::deserialise(ByteSpan data) {
    if (data.size() < kHeaderSize) {
        return err<Fragment>(ErrorCode::InvalidArgument,
            "Fragment too short to contain header");
    }
    Fragment f;
    f.stream_id      = (static_cast<std::uint16_t>(data[0]) << 8) |
                        static_cast<std::uint16_t>(data[1]);
    f.fragment_index  = static_cast<std::uint8_t>(data[2]);
    f.total_fragments = static_cast<std::uint8_t>(data[3]);
    f.payload         = Bytes(data.begin() + kHeaderSize, data.end());
    return ok<Fragment>(std::move(f));
}

// ── fragment_message ──────────────────────────────────────────────────────────

Result<std::vector<Fragment>> fragment_message(ByteSpan message,
                                                std::size_t mtu,
                                                StreamId stream_id) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::PacketEncoding);
    if (mtu <= Fragment::kHeaderSize) {
        return err<std::vector<Fragment>>(ErrorCode::InvalidArgument,
            "MTU must be larger than fragment header size (4 bytes)");
    }

    const std::size_t payload_per_fragment = mtu - Fragment::kHeaderSize;
    const std::size_t total = (message.size() + payload_per_fragment - 1) / payload_per_fragment;

    if (total > 255) {
        return err<std::vector<Fragment>>(ErrorCode::InvalidArgument,
            "Message too large to fragment into ≤255 pieces at this MTU");
    }
    if (total == 0 && message.empty()) {
        // Empty message: one empty fragment
        Fragment f;
        f.stream_id       = stream_id;
        f.fragment_index  = 0;
        f.total_fragments = 1;
        return ok<std::vector<Fragment>>(std::vector<Fragment>{std::move(f)});
    }

    std::vector<Fragment> fragments;
    fragments.reserve(total);

    const std::uint8_t total_u8 = static_cast<std::uint8_t>(total);
    for (std::uint8_t i = 0; i < total_u8; ++i) {
        const std::size_t offset = static_cast<std::size_t>(i) * payload_per_fragment;
        const std::size_t slice_size = std::min(payload_per_fragment, message.size() - offset);
        Fragment f;
        f.stream_id       = stream_id;
        f.fragment_index  = i;
        f.total_fragments = total_u8;
        f.payload = Bytes(message.begin() + static_cast<std::ptrdiff_t>(offset),
                          message.begin() + static_cast<std::ptrdiff_t>(offset + slice_size));
        fragments.push_back(std::move(f));
    }

    UAV_PQC_LOG_TRACE("transport.fragment", "Fragmented stream={} size={} into {} fragments",
                      stream_id, message.size(), total);
    return ok<std::vector<Fragment>>(std::move(fragments));
}

// ── FragmentReassembler ───────────────────────────────────────────────────────

FragmentReassembler::FragmentReassembler(Timestamp timeout_ms)
    : timeout_ms_(timeout_ms) {}

Result<std::optional<Bytes>> FragmentReassembler::feed(const Fragment& fragment,
                                                        Timestamp now_ms) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::PacketDecoding);
    // Find or create stream state
    StreamState* state = nullptr;
    for (auto& s : streams_) {
        if (s.stream_id == fragment.stream_id) {
            state = &s;
            break;
        }
    }

    if (!state) {
        StreamState ns;
        ns.stream_id          = fragment.stream_id;
        ns.total_fragments    = fragment.total_fragments;
        ns.received.resize(fragment.total_fragments);
        ns.first_received_ms  = now_ms;
        streams_.push_back(std::move(ns));
        state = &streams_.back();
    }

    // Timeout check
    if (now_ms - state->first_received_ms > timeout_ms_) {
        streams_.erase(std::remove_if(streams_.begin(), streams_.end(),
            [&](const StreamState& s) { return s.stream_id == fragment.stream_id; }),
            streams_.end());
        return err<std::optional<Bytes>>(ErrorCode::ReassemblyFailed,
            "Fragment stream timed out");
    }

    // Bounds check
    if (fragment.fragment_index >= state->total_fragments) {
        return err<std::optional<Bytes>>(ErrorCode::ReassemblyFailed,
            "Fragment index out of range");
    }

    if (state->received[fragment.fragment_index].empty()) {
        state->received[fragment.fragment_index] = fragment.payload;
        ++state->received_count;
    }

    if (state->received_count == state->total_fragments) {
        // Reassemble
        Bytes message;
        for (const auto& chunk : state->received) {
            message.insert(message.end(), chunk.begin(), chunk.end());
        }
        const StreamId sid = fragment.stream_id;
        streams_.erase(std::remove_if(streams_.begin(), streams_.end(),
            [sid](const StreamState& s) { return s.stream_id == sid; }),
            streams_.end());
        complete_ = true;
        UAV_PQC_LOG_TRACE("transport.fragment", "Reassembled stream={} total={} bytes",
                          sid, message.size());
        return ok<std::optional<Bytes>>(std::optional<Bytes>(std::move(message)));
    }

    return ok<std::optional<Bytes>>(std::nullopt);
}

std::size_t FragmentReassembler::prune_expired(Timestamp now_ms) {
    const std::size_t before = streams_.size();
    streams_.erase(std::remove_if(streams_.begin(), streams_.end(),
        [&](const StreamState& s) {
            return (now_ms - s.first_received_ms) > timeout_ms_;
        }), streams_.end());
    return before - streams_.size();
}

std::size_t FragmentReassembler::pending_streams() const noexcept {
    return streams_.size();
}

} // namespace uav_pqc::transport
