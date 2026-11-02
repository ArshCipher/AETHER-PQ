// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file transport.hpp
 * @brief Abstract transport layer abstraction and backends.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstddef>
#include <functional>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <atomic>

#ifdef UAV_PQC_ENABLE_NS3
#include <ns3/ptr.h>
#include <ns3/socket.h>
#else
namespace ns3 {
    template <typename T> class Ptr;
    class Socket;
}
#endif

namespace uav_pqc::transport {

/**
 * @brief Abstract bidirectional transport interface.
 */
class ITransport {
public:
    using ReceiveCallback = std::function<void(const NodeId& sender, Bytes data)>;

    ITransport()                                 = default;
    ITransport(const ITransport&)                = delete;
    ITransport& operator=(const ITransport&)     = delete;
    ITransport(ITransport&&) noexcept            = default;
    ITransport& operator=(ITransport&&) noexcept = default;
    virtual ~ITransport()                        = default;

    /**
     * @brief Connect the transport to a specific local or remote address string.
     */
    [[nodiscard]] virtual VoidResult connect(const std::string& address) = 0;

    /**
     * @brief Disconnect the transport and close resources.
     */
    [[nodiscard]] virtual VoidResult disconnect() = 0;

    /**
     * @brief Returns true if currently active / connected.
     */
    [[nodiscard]] virtual bool is_connected() const noexcept = 0;

    /**
     * @brief Send data asynchronously to a specific NodeId destination.
     */
    [[nodiscard]] virtual VoidResult send(const NodeId& destination, ByteSpan data) = 0;

    /**
     * @brief Broadcast data to all nodes.
     */
    [[nodiscard]] virtual VoidResult broadcast(ByteSpan data) = 0;

    /**
     * @brief Multicast data to a list of NodeId destinations.
     */
    [[nodiscard]] virtual VoidResult multicast(const std::vector<NodeId>& destinations, ByteSpan data) = 0;

    /**
     * @brief Register the callback for incoming data.
     */
    virtual void set_receive_handler(ReceiveCallback cb) = 0;
};

/**
 * @brief LocalProcessTransport for software simulation in-memory loopback.
 */
class LocalProcessTransport final : public ITransport {
public:
    explicit LocalProcessTransport(const NodeId& self_id);
    ~LocalProcessTransport() override;

    VoidResult connect(const std::string& address) override;
    VoidResult disconnect() override;
    bool is_connected() const noexcept override;

    VoidResult send(const NodeId& destination, ByteSpan data) override;
    VoidResult broadcast(ByteSpan data) override;
    VoidResult multicast(const std::vector<NodeId>& destinations, ByteSpan data) override;

    void set_receive_handler(ReceiveCallback cb) override;

    // Package delivery hook
    void deliver_packet(const NodeId& sender, Bytes data);

private:
    struct NodeIdHash {
        std::size_t operator()(const NodeId& id) const noexcept {
            std::size_t hash = 0;
            for (auto b : id) {
                hash = (hash * 31) + static_cast<std::size_t>(b);
            }
            return hash;
        }
    };

    NodeId self_id_;
    bool connected_ = false;
    ReceiveCallback rx_cb_;
    mutable std::mutex mutex_;

    // Static registry mapping NodeIds to active LocalProcessTransport instances
    static std::unordered_map<NodeId, LocalProcessTransport*, NodeIdHash> registry_;
    static std::mutex registry_mutex_;
};

/**
 * @brief LinuxSocketTransport implementing UDP sockets for hardware deployment.
 */
class LinuxSocketTransport final : public ITransport {
public:
    LinuxSocketTransport();
    ~LinuxSocketTransport() override;

    VoidResult connect(const std::string& address) override;
    VoidResult disconnect() override;
    bool is_connected() const noexcept override;

    VoidResult send(const NodeId& destination, ByteSpan data) override;
    VoidResult broadcast(ByteSpan data) override;
    VoidResult multicast(const std::vector<NodeId>& destinations, ByteSpan data) override;

    void set_receive_handler(ReceiveCallback cb) override;

    // Registers dynamic routes to map NodeIds to IP/Port endpoints
    void add_route(const NodeId& node_id, const std::string& ip, uint16_t port);

private:
    struct RemoteEndpoint {
        std::string ip;
        uint16_t port;
    };

    struct NodeIdHash {
        std::size_t operator()(const NodeId& id) const noexcept {
            std::size_t hash = 0;
            for (auto b : id) {
                hash = (hash * 31) + static_cast<std::size_t>(b);
            }
            return hash;
        }
    };

    void receive_loop();

    int socket_fd_ = -1;
    bool connected_ = false;
    ReceiveCallback rx_cb_;
    std::thread rx_thread_;
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    std::unordered_map<NodeId, RemoteEndpoint, NodeIdHash> routing_table_;
};

/**
 * @brief Ns3Transport adapter for ns-3 network simulator integration.
 */
class Ns3Transport final : public ITransport {
public:
    Ns3Transport();
    ~Ns3Transport() override;

    VoidResult connect(const std::string& address) override;
    VoidResult disconnect() override;
    bool is_connected() const noexcept override;

    VoidResult send(const NodeId& destination, ByteSpan data) override;
    VoidResult broadcast(ByteSpan data) override;
    VoidResult multicast(const std::vector<NodeId>& destinations, ByteSpan data) override;

    void set_receive_handler(ReceiveCallback cb) override;

#ifdef UAV_PQC_ENABLE_NS3
    void bind_ns3_socket(ns3::Ptr<ns3::Socket> socket);
private:
    void HandleRead(ns3::Ptr<ns3::Socket> socket);
    ns3::Ptr<ns3::Socket> ns3_socket_;
#endif

private:
    bool connected_ = false;
    ReceiveCallback rx_cb_;
    mutable std::mutex mutex_;
};

} // namespace uav_pqc::transport
