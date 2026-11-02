// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/transport/fragment.hpp"
#include "uav_pqc/transport/retransmit.hpp"
#include "uav_pqc/transport/transport.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <mutex>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <unordered_map>

namespace uav_pqc::app {

/**
 * @brief Callback invoked when a complete application-layer message is reassembled.
 */
using MessageReceivedFn = std::function<void(const NodeId& sender, const Bytes& msg)>;

/**
 * @brief Raw packet transmitter callback (e.g. UDP send or simulation channel).
 */
using PacketTransmitFn = std::function<VoidResult(const Bytes& packet)>;

/**
 * @brief Abstract NetworkManager interface.
 */
class INetworkManager {
public:
    INetworkManager() = default;
    virtual ~INetworkManager() = default;

    INetworkManager(const INetworkManager&) = delete;
    INetworkManager& operator=(const INetworkManager&) = delete;
    INetworkManager(INetworkManager&&) noexcept = default;
    INetworkManager& operator=(INetworkManager&&) noexcept = default;

    virtual VoidResult send_message(ByteSpan message) = 0;
    virtual VoidResult send_message_to(const NodeId& destination, ByteSpan message) = 0;
    virtual void set_message_handler(MessageReceivedFn handler) = 0;
    virtual VoidResult handle_incoming_packet(ByteSpan packet, Timestamp now_ms, const NodeId& sender = {}) = 0;
    virtual void tick(Timestamp now_ms) = 0;
};

/**
 * @brief Concrete NetworkManager class managing socket/simulated transmission, MTU-aware fragmentation, and selective retransmission.
 */
class NetworkManager final : public INetworkManager {
public:
    NetworkManager(PacketTransmitFn transmit_fn, std::size_t mtu = 500, transport::StreamId start_stream_id = 0, std::shared_ptr<platform::IClock> clock = nullptr);
    NetworkManager(std::shared_ptr<transport::ITransport> transport, std::size_t mtu = 500, transport::StreamId start_stream_id = 0, std::shared_ptr<platform::IClock> clock = nullptr);
    ~NetworkManager() override = default;

    VoidResult send_message(ByteSpan message) override;
    VoidResult send_message_to(const NodeId& destination, ByteSpan message) override;
    void set_message_handler(MessageReceivedFn handler) override;
    VoidResult handle_incoming_packet(ByteSpan packet, Timestamp now_ms, const NodeId& sender = {}) override;
    void tick(Timestamp now_ms) override;

private:
    // Composite key: (sender NodeId, stream_id) — prevents stream-id collisions
    // between different UAVs that each start their own next_stream_id_ from 0.
    struct SenderStreamKey {
        NodeId sender;
        transport::StreamId stream_id;
        bool operator==(const SenderStreamKey& o) const noexcept {
            return stream_id == o.stream_id && sender == o.sender;
        }
    };
    struct SenderStreamHash {
        std::size_t operator()(const SenderStreamKey& k) const noexcept {
            std::size_t h = k.stream_id;
            for (auto b : k.sender) {
                h ^= static_cast<std::size_t>(b) + 0x9e3779b9 + (h << 6) + (h >> 2);
            }
            return h;
        }
    };

    PacketTransmitFn transmit_fn_;
    std::shared_ptr<transport::ITransport> transport_;
    std::size_t mtu_;
    transport::StreamId next_stream_id_ = 0;
    // Per-sender reassemblers: each remote node gets its own namespace.
    struct NodeIdHash {
        std::size_t operator()(const NodeId& id) const noexcept {
            std::size_t h = 0;
            for (auto b : id)
                h ^= static_cast<std::size_t>(b) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
    std::unordered_map<NodeId, transport::FragmentReassembler,
        NodeIdHash> reassemblers_;
    std::unique_ptr<transport::RetransmitManager> retransmitter_;
    MessageReceivedFn message_handler_;
    std::recursive_mutex mutex_;
    std::unordered_set<SenderStreamKey, SenderStreamHash> completed_streams_;
    std::unordered_map<SenderStreamKey, std::uint64_t, SenderStreamHash> received_bitmaps_;
    std::shared_ptr<platform::IClock> clock_;
};

} // namespace uav_pqc::app
