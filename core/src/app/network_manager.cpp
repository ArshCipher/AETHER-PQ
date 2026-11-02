#include "uav_pqc/app/network_manager.hpp"
#include "uav_pqc/platform/clock.hpp"
#include <unordered_map>
#include <chrono>
#include <thread>

namespace uav_pqc::app {

NetworkManager::NetworkManager(PacketTransmitFn transmit_fn, std::size_t mtu, transport::StreamId start_stream_id, std::shared_ptr<platform::IClock> clock)
    : transmit_fn_(std::move(transmit_fn)), mtu_(mtu), next_stream_id_(start_stream_id), clock_(clock) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    retransmitter_ = std::make_unique<transport::RetransmitManager>(
        [this](const transport::Fragment& frag) -> VoidResult {
            return transmit_fn_(frag.serialise());
        },
        1000, // 1000ms retry timeout
        20,   // max 20 timer-based retries (robust over lossy wireless)
        clock_
    );
}

NetworkManager::NetworkManager(std::shared_ptr<transport::ITransport> transport, std::size_t mtu, transport::StreamId start_stream_id, std::shared_ptr<platform::IClock> clock)
    : transport_(std::move(transport)), mtu_(mtu), next_stream_id_(start_stream_id), clock_(clock) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    
    transmit_fn_ = [this](const Bytes& packet) -> VoidResult {
        if (transport_) {
            return transport_->broadcast(packet);
        }
        return ok();
    };

    retransmitter_ = std::make_unique<transport::RetransmitManager>(
        [this](const transport::Fragment& frag) -> VoidResult {
            return transmit_fn_(frag.serialise());
        },
        1000, // 1000ms retry timeout
        20,   // max 20 timer-based retries (robust over lossy wireless)
        clock_
    );

    transport_->set_receive_handler([this](const NodeId& sender, Bytes data) {
        (void)handle_incoming_packet(data, clock_->now_ms(), sender);
    });
}

VoidResult NetworkManager::send_message(ByteSpan message) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    transport::StreamId stream_id = next_stream_id_++;
    auto frags_r = transport::fragment_message(message, mtu_, stream_id);
    if (!frags_r) return err(frags_r.error());

    auto& fragments = frags_r.value();
    // Register fragments with retransmitter first
    auto track_res = retransmitter_->track_stream(stream_id, fragments);
    if (!track_res) return track_res;

    // Send the fragments initially with a small delay to avoid buffer overflow
    for (const auto& frag : fragments) {
        auto transmit_res = transmit_fn_(frag.serialise());
        if (!transmit_res) return transmit_res;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    return ok();
}

VoidResult NetworkManager::send_message_to(const NodeId& destination, ByteSpan message) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    transport::StreamId stream_id = next_stream_id_++;
    auto frags_r = transport::fragment_message(message, mtu_, stream_id);
    if (!frags_r) return err(frags_r.error());

    auto& fragments = frags_r.value();

    // Register with retransmitter using a destination-aware send function,
    // so missing fragments can be recovered by the timer-based tick().
    auto dest_copy = destination;
    auto track_res = retransmitter_->track_stream(
        stream_id,
        fragments,
        [this, dest_copy](const transport::Fragment& frag) -> VoidResult {
            if (transport_) {
                return transport_->send(dest_copy, frag.serialise());
            }
            return transmit_fn_(frag.serialise());
        }
    );
    if (!track_res) return track_res;

    for (const auto& frag : fragments) {
        VoidResult transmit_res;
        if (transport_) {
            transmit_res = transport_->send(destination, frag.serialise());
        } else {
            transmit_res = transmit_fn_(frag.serialise());
        }
        if (!transmit_res) return transmit_res;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    return ok();
}

void NetworkManager::set_message_handler(MessageReceivedFn handler) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    message_handler_ = std::move(handler);
}

VoidResult NetworkManager::handle_incoming_packet(ByteSpan packet, Timestamp now_ms, const NodeId& sender) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // If it's a FragmentAck (exactly 10 bytes)
    if (packet.size() == 10) {
        auto ack_r = transport::FragmentAck::deserialise(packet);
        if (ack_r) {
            return retransmitter_->process_ack(ack_r.value(), now_ms);
        }
    }

    // Otherwise, parse as Fragment
    auto frag_r = transport::Fragment::deserialise(packet);
    if (!frag_r) return err(frag_r.error());

    const auto& frag = frag_r.value();

    // Check if this is a restart/handshake start stream ID:
    // If sender is GCS (all zeros), GCS handshake starts at 50000.
    // If sender is UAV, UAV handshake starts at uav_index * 10000.
    bool is_handshake_start = false;
    bool is_gcs = true;
    for (auto b : sender) {
        if (static_cast<uint8_t>(b) != 0) {
            is_gcs = false;
            break;
        }
    }
    if (is_gcs) {
        if (frag.stream_id == 50000) {
            is_handshake_start = true;
        }
    } else {
        uint16_t uav_index = (static_cast<uint16_t>(sender[0]) << 8) | static_cast<uint16_t>(sender[1]);
        if (frag.stream_id == uav_index * 10000) {
            is_handshake_start = true;
        }
    }

    if (is_handshake_start) {
        for (auto it = completed_streams_.begin(); it != completed_streams_.end(); ) {
            if (it->sender == sender) {
                it = completed_streams_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = received_bitmaps_.begin(); it != received_bitmaps_.end(); ) {
            if (it->first.sender == sender) {
                it = received_bitmaps_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Key by (sender, stream_id) to prevent collisions between UAVs that
    // each start their own next_stream_id_ counter from 0.
    SenderStreamKey key{sender, frag.stream_id};

    if (completed_streams_.count(key)) {
        transport::FragmentAck ack{
            .stream_id = frag.stream_id,
            .bitmap = 0xFFFFFFFFFFFFFFFFULL
        };
        if (transport_ && sender != NodeId{}) {
            (void)transport_->send(sender, ack.serialise());
        } else {
            (void)transmit_fn_(ack.serialise());
        }
        return ok();
    }

    // Update our ACK bitmap for this (sender, stream) key
    {
        received_bitmaps_[key] |= (1ULL << frag.fragment_index);

        // Send back an ACK immediately to the specific sender
        transport::FragmentAck ack{
            .stream_id = frag.stream_id,
            .bitmap = received_bitmaps_[key]
        };
        if (transport_ && sender != NodeId{}) {
            (void)transport_->send(sender, ack.serialise());
        } else {
            (void)transmit_fn_(ack.serialise());
        }
    }

    // Feed to the per-sender reassembler
    auto& reassembler = reassemblers_[sender];
    auto reassemble_r = reassembler.feed(frag, now_ms);
    if (!reassemble_r) return err(reassemble_r.error());

    if (reassemble_r.value().has_value()) {
        // Complete message reassembled!
        completed_streams_.insert(key);
        // Use a large window (5000) to avoid premature eviction that would
        // cause stream ID collisions between handshake and subsequent command packets
        if (completed_streams_.size() > 5000) {
            completed_streams_.clear();
        }
        {
            received_bitmaps_.erase(key);
        }
        if (message_handler_) {
            message_handler_(sender, reassemble_r.value().value());
        }
    }

    return ok();
}

void NetworkManager::tick(Timestamp now_ms) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    retransmitter_->tick(now_ms);
    for (auto& [id, reassembler] : reassemblers_) {
        reassembler.prune_expired(now_ms);
    }
}

} // namespace uav_pqc::app
