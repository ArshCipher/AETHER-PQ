// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/transport/transport.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"
#include <iostream>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifdef UAV_PQC_ENABLE_NS3
#include <ns3/socket.h>
#include <ns3/packet.h>
#include <ns3/address.h>
#include <ns3/inet-socket-address.h>
#endif

namespace uav_pqc::transport {

// ─────────────────────────────────────────────────────────────────────────────
// LocalProcessTransport Implementation
// ─────────────────────────────────────────────────────────────────────────────

std::unordered_map<NodeId, LocalProcessTransport*, LocalProcessTransport::NodeIdHash> LocalProcessTransport::registry_;
std::mutex LocalProcessTransport::registry_mutex_;

LocalProcessTransport::LocalProcessTransport(const NodeId& self_id) : self_id_(self_id) {
    std::lock_guard<std::mutex> lock(registry_mutex_);
    registry_[self_id_] = this;
}

LocalProcessTransport::~LocalProcessTransport() {
    (void)disconnect();
    std::lock_guard<std::mutex> lock(registry_mutex_);
    registry_.erase(self_id_);
}

VoidResult LocalProcessTransport::connect(const std::string&) {
    std::lock_guard<std::mutex> lock(mutex_);
    connected_ = true;
    return ok();
}

VoidResult LocalProcessTransport::disconnect() {
    std::lock_guard<std::mutex> lock(mutex_);
    connected_ = false;
    return ok();
}

bool LocalProcessTransport::is_connected() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return connected_;
}

VoidResult LocalProcessTransport::send(const NodeId& destination, ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SocketSend);
    auto& collector = diagnostics::MetricsCollector::get_instance();
    collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketSize, static_cast<double>(data.size()));
    collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::BytesTransmitted, static_cast<double>(data.size()));
    collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketsTransmitted, 1.0);

    LocalProcessTransport* dest_transport = nullptr;
    {
        std::lock_guard<std::mutex> registry_lock(registry_mutex_);
        auto it = registry_.find(destination);
        if (it != registry_.end()) {
            dest_transport = it->second;
        }
    }

    if (dest_transport) {
        Bytes copy_data(data.begin(), data.end());
        NodeId sender = self_id_;
        std::thread([dest_transport, sender, copy_data = std::move(copy_data)]() {
            dest_transport->deliver_packet(sender, copy_data);
        }).detach();
    }
    return ok();
}

VoidResult LocalProcessTransport::broadcast(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SocketSend);
    auto& collector = diagnostics::MetricsCollector::get_instance();

    std::vector<LocalProcessTransport*> targets;
    {
        std::lock_guard<std::mutex> registry_lock(registry_mutex_);
        for (const auto& [id, transport] : registry_) {
            if (id != self_id_) {
                targets.push_back(transport);
            }
        }
    }

    if (!targets.empty()) {
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketSize, static_cast<double>(data.size()));
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::BytesTransmitted, static_cast<double>(data.size() * targets.size()));
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketsTransmitted, static_cast<double>(targets.size()));
    }

    for (auto* dest : targets) {
        Bytes copy_data(data.begin(), data.end());
        NodeId sender = self_id_;
        std::thread([dest, sender, copy_data = std::move(copy_data)]() {
            dest->deliver_packet(sender, copy_data);
        }).detach();
    }
    return ok();
}

VoidResult LocalProcessTransport::multicast(const std::vector<NodeId>& destinations, ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SocketSend);
    auto& collector = diagnostics::MetricsCollector::get_instance();

    std::vector<LocalProcessTransport*> targets;
    {
        std::lock_guard<std::mutex> registry_lock(registry_mutex_);
        for (const auto& dest : destinations) {
            auto it = registry_.find(dest);
            if (it != registry_.end()) {
                targets.push_back(it->second);
            }
        }
    }

    if (!targets.empty()) {
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketSize, static_cast<double>(data.size()));
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::BytesTransmitted, static_cast<double>(data.size() * targets.size()));
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketsTransmitted, static_cast<double>(targets.size()));
    }

    for (auto* dest : targets) {
        Bytes copy_data(data.begin(), data.end());
        NodeId sender = self_id_;
        std::thread([dest, sender, copy_data = std::move(copy_data)]() {
            dest->deliver_packet(sender, copy_data);
        }).detach();
    }
    return ok();
}

void LocalProcessTransport::set_receive_handler(ReceiveCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    rx_cb_ = std::move(cb);
}

void LocalProcessTransport::deliver_packet(const NodeId& sender, Bytes data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SocketReceive);
    auto& collector = diagnostics::MetricsCollector::get_instance();
    collector.record(diagnostics::OpKind::SocketReceive, diagnostics::MetricType::PacketSize, static_cast<double>(data.size()));

    ReceiveCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!connected_) return;
        cb = rx_cb_;
    }
    if (cb) {
        cb(sender, std::move(data));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinuxSocketTransport Implementation
// ─────────────────────────────────────────────────────────────────────────────

LinuxSocketTransport::LinuxSocketTransport() = default;

LinuxSocketTransport::~LinuxSocketTransport() {
    (void)disconnect();
}

VoidResult LinuxSocketTransport::connect(const std::string& address) {
#ifdef _WIN32
    (void)address;
    return err(ErrorCode::TransportError);
#else
    std::lock_guard<std::mutex> lock(mutex_);
    if (connected_) return ok();

    std::string ip = "0.0.0.0";
    uint16_t port = 0;
    auto colon = address.find(':');
    if (colon != std::string::npos) {
        ip = address.substr(0, colon);
        port = static_cast<uint16_t>(std::stoul(address.substr(colon + 1)));
    } else {
        port = static_cast<uint16_t>(std::stoul(address));
    }

    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        return err(ErrorCode::TransportError);
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Increase send and receive buffers to prevent packet drops under back-to-back load
    int rcvbuf = 10 * 1024 * 1024;
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int sndbuf = 10 * 1024 * 1024;
    setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    // Set receive timeout to 100ms to prevent indefinite blocking in recvfrom on Linux
    struct timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
        close(socket_fd_);
        socket_fd_ = -1;
        return err(ErrorCode::TransportError);
    }

    running_ = true;
    connected_ = true;
    rx_thread_ = std::thread(&LinuxSocketTransport::receive_loop, this);

    return ok();
#endif
}

VoidResult LinuxSocketTransport::disconnect() {
#ifndef _WIN32
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!connected_) return ok();
        running_ = false;
        connected_ = false;
        if (socket_fd_ >= 0) {
            close(socket_fd_);
        }
    }

    if (rx_thread_.joinable()) {
        rx_thread_.join();
    }
    socket_fd_ = -1;
#endif
    return ok();
}

bool LinuxSocketTransport::is_connected() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return connected_;
}

VoidResult LinuxSocketTransport::send(const NodeId& destination, ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SocketSend);
    auto& collector = diagnostics::MetricsCollector::get_instance();
#ifdef _WIN32
    (void)destination;
    (void)data;
    return err(ErrorCode::TransportError);
#else
    std::lock_guard<std::mutex> lock(mutex_);
    if (!connected_ || socket_fd_ < 0) {
        return err(ErrorCode::TransportError);
    }

    auto it = routing_table_.find(destination);
    if (it == routing_table_.end()) {
        return err(ErrorCode::TransportError);
    }

    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(it->second.port);
    std::string dest_ip = it->second.ip;
    if (dest_ip == "0.0.0.0") {
        dest_ip = "127.0.0.1";
    }
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip.c_str());

    ssize_t sent = sendto(socket_fd_, data.data(), data.size(), 0,
                          reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr));
    if (sent < 0) {
        return err(ErrorCode::TransportError);
    }

    collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketSize, static_cast<double>(data.size()));
    collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::BytesTransmitted, static_cast<double>(data.size()));
    collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketsTransmitted, 1.0);

    return ok();
#endif
}

VoidResult LinuxSocketTransport::broadcast(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SocketSend);
    auto& collector = diagnostics::MetricsCollector::get_instance();
#ifdef _WIN32
    (void)data;
    return err(ErrorCode::TransportError);
#else
    std::lock_guard<std::mutex> lock(mutex_);
    if (!connected_ || socket_fd_ < 0) {
        return err(ErrorCode::TransportError);
    }

    std::size_t count = 0;
    for (const auto& [id, endpoint] : routing_table_) {
        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(endpoint.port);
        std::string dest_ip = endpoint.ip;
        if (dest_ip == "0.0.0.0") {
            dest_ip = "127.0.0.1";
        }
        dest_addr.sin_addr.s_addr = inet_addr(dest_ip.c_str());

        if (sendto(socket_fd_, data.data(), data.size(), 0,
               reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr)) >= 0) {
            count++;
        }
    }

    if (count > 0) {
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketSize, static_cast<double>(data.size()));
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::BytesTransmitted, static_cast<double>(data.size() * count));
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketsTransmitted, static_cast<double>(count));
    }

    return ok();
#endif
}

VoidResult LinuxSocketTransport::multicast(const std::vector<NodeId>& destinations, ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SocketSend);
    auto& collector = diagnostics::MetricsCollector::get_instance();
#ifdef _WIN32
    (void)destinations;
    (void)data;
    return err(ErrorCode::TransportError);
#else
    std::lock_guard<std::mutex> lock(mutex_);
    if (!connected_ || socket_fd_ < 0) {
        return err(ErrorCode::TransportError);
    }

    std::size_t count = 0;
    for (const auto& dest : destinations) {
        auto it = routing_table_.find(dest);
        if (it != routing_table_.end()) {
            sockaddr_in dest_addr{};
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = htons(it->second.port);
            dest_addr.sin_addr.s_addr = inet_addr(it->second.ip.c_str());

            if (sendto(socket_fd_, data.data(), data.size(), 0,
                   reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr)) >= 0) {
                count++;
            }
        }
    }

    if (count > 0) {
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketSize, static_cast<double>(data.size()));
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::BytesTransmitted, static_cast<double>(data.size() * count));
        collector.record(diagnostics::OpKind::SocketSend, diagnostics::MetricType::PacketsTransmitted, static_cast<double>(count));
    }

    return ok();
#endif
}

void LinuxSocketTransport::set_receive_handler(ReceiveCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    rx_cb_ = std::move(cb);
}

void LinuxSocketTransport::add_route(const NodeId& node_id, const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    routing_table_[node_id] = RemoteEndpoint{ip, port};
}

void LinuxSocketTransport::receive_loop() {
#ifndef _WIN32
    std::vector<uint8_t> buffer(65535);
    while (running_) {
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);

        ssize_t received = recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                    reinterpret_cast<sockaddr*>(&from_addr), &from_len);
        if (received < 0) {
            if (!running_) break;
            continue;
        }

        ReceiveCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = rx_cb_;
        }

        if (cb) {
            diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SocketReceive);
            auto& collector = diagnostics::MetricsCollector::get_instance();
            collector.record(diagnostics::OpKind::SocketReceive, diagnostics::MetricType::PacketSize, static_cast<double>(received));

            Bytes packet(received);
            std::transform(buffer.begin(), buffer.begin() + received, packet.begin(),
                           [](uint8_t b) { return static_cast<std::byte>(b); });

            // Try to match sender IP/port to a NodeId route
            NodeId sender_id{};
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
            uint16_t port = ntohs(from_addr.sin_port);

            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (const auto& [id, endpoint] : routing_table_) {
                    if ((endpoint.ip == ip_str || endpoint.ip == "0.0.0.0") && endpoint.port == port) {
                        sender_id = id;
                        break;
                    }
                }
            }


            cb(sender_id, std::move(packet));
        }
    }
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// Ns3Transport Implementation
// ─────────────────────────────────────────────────────────────────────────────

Ns3Transport::Ns3Transport() = default;

Ns3Transport::~Ns3Transport() {
    (void)disconnect();
}

VoidResult Ns3Transport::connect(const std::string&) {
    std::lock_guard<std::mutex> lock(mutex_);
    connected_ = true;
    return ok();
}

VoidResult Ns3Transport::disconnect() {
    std::lock_guard<std::mutex> lock(mutex_);
    connected_ = false;
    return ok();
}

bool Ns3Transport::is_connected() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return connected_;
}

VoidResult Ns3Transport::send(const NodeId& destination, ByteSpan data) {
    (void)destination;
    (void)data;
#ifdef UAV_PQC_ENABLE_NS3
    std::lock_guard<std::mutex> lock(mutex_);
    if (!connected_ || !ns3_socket_) {
        return err(common::ErrorCode::TransportError);
    }
    // Implement standard ns3 socket send in future integration
#endif
    return ok();
}

VoidResult Ns3Transport::broadcast(ByteSpan data) {
    (void)data;
#ifdef UAV_PQC_ENABLE_NS3
    // Send to broadcast address in ns-3
#endif
    return ok();
}

VoidResult Ns3Transport::multicast(const std::vector<NodeId>& destinations, ByteSpan data) {
    (void)destinations;
    (void)data;
    return ok();
}

void Ns3Transport::set_receive_handler(ReceiveCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    rx_cb_ = std::move(cb);
}

#ifdef UAV_PQC_ENABLE_NS3
void Ns3Transport::bind_ns3_socket(ns3::Ptr<ns3::Socket> socket) {
    std::lock_guard<std::mutex> lock(mutex_);
    ns3_socket_ = socket;
    ns3_socket_->SetRecvCallback(ns3::MakeCallback(&Ns3Transport::HandleRead, this));
}

void Ns3Transport::HandleRead(ns3::Ptr<ns3::Socket> socket) {
    ns3::Ptr<ns3::Packet> packet;
    ns3::Address from;
    while ((packet = socket->RecvFrom(from))) {
        std::size_t psize = packet->GetSize();
        Bytes buf(psize);
        packet->CopyData(reinterpret_cast<uint8_t*>(buf.data()), psize);

        ReceiveCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = rx_cb_;
        }

        if (cb) {
            NodeId sender_id{}; // resolved in simulation
            cb(sender_id, std::move(buf));
        }
    }
}
#endif

} // namespace uav_pqc::transport
