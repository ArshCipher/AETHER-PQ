// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file channel.hpp
 * @brief Abstract transport channel interface.
 *
 * Decouples the protocol stack from the physical transport medium.
 * The same protocol code runs over:
 *  - UDP sockets (Linux/RPi)
 *  - ns-3 simulated channels (ns3::Socket)
 *  - Serial/CAN links (STM32)
 *
 * The channel operates on raw byte buffers.  The fragment layer handles
 * MTU adaptation above the channel.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstddef>
#include <functional>

namespace uav_pqc::transport {

/**
 * @brief Maximum transmission unit hint provided by the channel.
 *
 * The fragment layer uses this to split messages that exceed the MTU.
 */
struct ChannelMtu {
    std::size_t bytes;       ///< Maximum payload bytes per packet
    bool        reliable;    ///< True if the channel guarantees delivery (TCP/serial)
};

/**
 * @brief Abstract bidirectional byte channel.
 *
 * Implementations: UdpChannel (Linux), Ns3Channel (ns-3 shim).
 */
class IChannel {
public:
    /// Callback type for received data.
    using ReceiveFn = std::function<void(Bytes data, NodeId sender)>;

    IChannel()                                 = default;
    IChannel(const IChannel&)                  = delete;
    IChannel& operator=(const IChannel&)       = delete;
    IChannel(IChannel&&) noexcept              = default;
    IChannel& operator=(IChannel&&) noexcept   = default;
    virtual ~IChannel()                         = default;

    /**
     * @brief Send bytes to a specific peer.
     *
     * May fragment internally if the underlying transport requires it.
     * Non-blocking where possible.
     *
     * @param data       Payload to send.
     * @param peer       Destination NodeId.
     * @return           Ok or TransportError.
     */
    [[nodiscard]] virtual VoidResult send(Bytes data, const NodeId& peer) = 0;

    /**
     * @brief Register the callback for incoming data.
     *
     * Called zero or more times per receive event.  The callback receives
     * the raw bytes and the sender's NodeId.
     */
    virtual void set_receive_handler(ReceiveFn fn) = 0;

    /**
     * @brief Returns the effective MTU for this channel.
     */
    [[nodiscard]] virtual ChannelMtu mtu() const noexcept = 0;

    /// Returns true if the channel is currently connected / open.
    [[nodiscard]] virtual bool is_open() const noexcept = 0;
};

} // namespace uav_pqc::transport
