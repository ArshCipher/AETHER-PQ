// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/types.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/protocol/mode.hpp"
#include "uav_pqc/policy/profile.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/identity/certificate.hpp"
#include "uav_pqc/group/group_key.hpp"
#include "uav_pqc/session/session.hpp"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <array>
#include <optional>
#include <cstddef>
#include <cstdint>

namespace uav_pqc::types {

// ── 1. Timestamp ─────────────────────────────────────────────────────────────
class Timestamp {
public:
    Timestamp() = default;
    explicit Timestamp(uav_pqc::Timestamp val) : val_(val) {}

    [[nodiscard]] uav_pqc::Timestamp value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<Timestamp> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const Timestamp& other) const noexcept { return val_ == other.val_; }
#if defined(__cpp_impl_three_way_comparison) || (defined(__cplusplus) && __cplusplus >= 202002L)
    bool operator<=>(const Timestamp& other) const noexcept = default;
#else
    bool operator<(const Timestamp& other) const noexcept { return val_ < other.val_; }
    bool operator>(const Timestamp& other) const noexcept { return val_ > other.val_; }
    bool operator<=(const Timestamp& other) const noexcept { return val_ <= other.val_; }
    bool operator>=(const Timestamp& other) const noexcept { return val_ >= other.val_; }
#endif

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<Timestamp> from_json(const nlohmann::json& j);

private:
    uav_pqc::Timestamp val_ = 0;
};

// ── 2. NodeID ────────────────────────────────────────────────────────────────
class NodeID {
public:
    NodeID() = default;
    explicit NodeID(const NodeId& val) : val_(val) {}

    [[nodiscard]] const NodeId& value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<NodeID> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const NodeID& other) const noexcept { return val_ == other.val_; }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<NodeID> from_json(const nlohmann::json& j);

private:
    NodeId val_{};
};

// ── 3. SessionID ─────────────────────────────────────────────────────────────
class SessionID {
public:
    SessionID() = default;
    explicit SessionID(const SessionId& val) : val_(val) {}

    [[nodiscard]] const SessionId& value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<SessionID> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const SessionID& other) const noexcept { return val_ == other.val_; }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<SessionID> from_json(const nlohmann::json& j);

private:
    SessionId val_{};
};

// ── 4. Nonce ─────────────────────────────────────────────────────────────────
class Nonce {
public:
    Nonce() = default;
    explicit Nonce(const std::array<std::byte, 12>& val) : val_(val) {}

    [[nodiscard]] const std::array<std::byte, 12>& value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<Nonce> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const Nonce& other) const noexcept { return val_ == other.val_; }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<Nonce> from_json(const nlohmann::json& j);

private:
    std::array<std::byte, 12> val_{};
};

// ── 5. OperatingMode ─────────────────────────────────────────────────────────
class OperatingMode {
public:
    OperatingMode() = default;
    explicit OperatingMode(protocol::OperatingMode val) : val_(val) {}

    [[nodiscard]] protocol::OperatingMode value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<OperatingMode> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const OperatingMode& other) const noexcept { return val_ == other.val_; }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<OperatingMode> from_json(const nlohmann::json& j);

private:
    protocol::OperatingMode val_ = protocol::OperatingMode::Classical;
};

// ── 6. CryptoProfile ─────────────────────────────────────────────────────────
class CryptoProfile {
public:
    CryptoProfile() = default;
    explicit CryptoProfile(policy::CryptographicProfile val) : val_(val) {}

    [[nodiscard]] policy::CryptographicProfile value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<CryptoProfile> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const CryptoProfile& other) const noexcept { return val_ == other.val_; }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<CryptoProfile> from_json(const nlohmann::json& j);

private:
    policy::CryptographicProfile val_ = policy::CryptographicProfile::Standard;
};

// ── 7. CipherSuite ───────────────────────────────────────────────────────────
class CipherSuite {
public:
    CipherSuite() = default;
    explicit CipherSuite(const protocol::CipherSuite& val) : val_(val) {}

    [[nodiscard]] const protocol::CipherSuite& value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<CipherSuite> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const CipherSuite& other) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<CipherSuite> from_json(const nlohmann::json& j);

private:
    protocol::CipherSuite val_;
};

// ── 8. ProtocolVersion ───────────────────────────────────────────────────────
class ProtocolVersion {
public:
    ProtocolVersion() = default;
    ProtocolVersion(std::uint8_t major, std::uint8_t minor) : major_(major), minor_(minor) {}

    [[nodiscard]] std::uint8_t major_v() const noexcept { return major_; }
    [[nodiscard]] std::uint8_t minor_v() const noexcept { return minor_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<ProtocolVersion> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const ProtocolVersion& other) const noexcept {
        return major_ == other.major_ && minor_ == other.minor_;
    }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<ProtocolVersion> from_json(const nlohmann::json& j);

private:
    std::uint8_t major_ = 1;
    std::uint8_t minor_ = 0;
};

// ── 9. MissionType ───────────────────────────────────────────────────────────
class MissionType {
public:
    enum class Type : std::uint8_t {
        Civilian = 0,
        Commercial = 1,
        Military = 2
    };

    MissionType() = default;
    explicit MissionType(Type val) : val_(val) {}

    [[nodiscard]] Type value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<MissionType> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const MissionType& other) const noexcept { return val_ == other.val_; }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<MissionType> from_json(const nlohmann::json& j);

private:
    Type val_ = Type::Civilian;
};

// ── 10. BatteryStatus ────────────────────────────────────────────────────────
class BatteryStatus {
public:
    BatteryStatus() = default;
    explicit BatteryStatus(double percent) : percent_(percent) {}

    [[nodiscard]] double percent() const noexcept { return percent_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<BatteryStatus> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const BatteryStatus& other) const noexcept { return percent_ == other.percent_; }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<BatteryStatus> from_json(const nlohmann::json& j);

private:
    double percent_ = 100.0;
};

// ── 11. NetworkMetrics ───────────────────────────────────────────────────────
class NetworkMetrics {
public:
    NetworkMetrics() = default;
    NetworkMetrics(double snr_db, double loss_rate) : snr_db_(snr_db), loss_rate_(loss_rate) {}

    [[nodiscard]] double snr_db() const noexcept { return snr_db_; }
    [[nodiscard]] double loss_rate() const noexcept { return loss_rate_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<NetworkMetrics> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const NetworkMetrics& other) const noexcept {
        return snr_db_ == other.snr_db_ && loss_rate_ == other.loss_rate_;
    }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<NetworkMetrics> from_json(const nlohmann::json& j);

private:
    double snr_db_ = 30.0;
    double loss_rate_ = 0.0;
};

// ── 12. Certificate ──────────────────────────────────────────────────────────
class Certificate {
public:
    Certificate() = default;
    explicit Certificate(const identity::Certificate& val) : val_(val) {}

    [[nodiscard]] const identity::Certificate& value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<Certificate> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const Certificate& other) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<Certificate> from_json(const nlohmann::json& j);

private:
    identity::Certificate val_;
};

// ── 13. CertificateChain ─────────────────────────────────────────────────────
class CertificateChain {
public:
    CertificateChain() = default;
    explicit CertificateChain(const std::vector<identity::Certificate>& val) : val_(val) {}

    [[nodiscard]] const std::vector<identity::Certificate>& value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<CertificateChain> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const CertificateChain& other) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<CertificateChain> from_json(const nlohmann::json& j);

private:
    std::vector<identity::Certificate> val_;
};

// ── 14. CertificateRevocation ────────────────────────────────────────────────
class CertificateRevocation {
public:
    CertificateRevocation() = default;
    CertificateRevocation(const NodeId& target, uav_pqc::Timestamp revoked_at)
        : target_(target), revoked_at_(revoked_at) {}

    [[nodiscard]] const NodeId& target() const noexcept { return target_; }
    [[nodiscard]] uav_pqc::Timestamp revoked_at() const noexcept { return revoked_at_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<CertificateRevocation> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const CertificateRevocation& other) const noexcept {
        return target_ == other.target_ && revoked_at_ == other.revoked_at_;
    }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<CertificateRevocation> from_json(const nlohmann::json& j);

private:
    NodeId target_{};
    uav_pqc::Timestamp revoked_at_ = 0;
};

// ── 15. TreeNode ─────────────────────────────────────────────────────────────
class TreeNode {
public:
    TreeNode() = default;
    TreeNode(std::uint32_t index, const crypto::KemPublicKey& key) : index_(index), key_(key) {}

    [[nodiscard]] std::uint32_t index() const noexcept { return index_; }
    [[nodiscard]] const crypto::KemPublicKey& key() const noexcept { return key_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<TreeNode> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const TreeNode& other) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<TreeNode> from_json(const nlohmann::json& j);

private:
    std::uint32_t index_ = 0;
    crypto::KemPublicKey key_;
};

// ── 16. PairwiseKey ──────────────────────────────────────────────────────────
class PairwiseKey {
public:
    PairwiseKey() = default;
    explicit PairwiseKey(SecureBytes val) : val_(std::move(val)) {}

    [[nodiscard]] const SecureBytes& value() const noexcept { return val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<PairwiseKey> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const PairwiseKey& other) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<PairwiseKey> from_json(const nlohmann::json& j);

private:
    SecureBytes val_;
};

// ── 17. GroupKey ─────────────────────────────────────────────────────────────
class GroupKey {
public:
    GroupKey() = default;
    explicit GroupKey(group::GroupKey val) : val_(std::move(val)) {}

    GroupKey(const GroupKey&)            = delete;
    GroupKey& operator=(const GroupKey&) = delete;
    GroupKey(GroupKey&&) noexcept        = default;
    GroupKey& operator=(GroupKey&&) noexcept = default;

    [[nodiscard]] const group::GroupKey& value() const noexcept { return *val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<GroupKey> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const GroupKey& other) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<GroupKey> from_json(const nlohmann::json& j);

private:
    std::optional<group::GroupKey> val_;
};

// ── 18. Session ──────────────────────────────────────────────────────────────
class Session {
public:
    Session() = default;
    explicit Session(session::Session val) : val_(std::move(val)) {}

    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) noexcept        = default;
    Session& operator=(Session&&) noexcept = default;

    [[nodiscard]] const session::Session& value() const noexcept { return *val_; }
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<Session> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const Session& other) const noexcept;

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<Session> from_json(const nlohmann::json& j);

private:
    std::optional<session::Session> val_;
};

// ── 19. PacketHeader ─────────────────────────────────────────────────────────
class PacketHeader {
public:
    PacketHeader() = default;
    PacketHeader(std::uint8_t type, const SessionId& session_id, std::uint64_t seq_num, std::uint16_t length)
        : type_(type), session_id_(session_id), seq_num_(seq_num), length_(length) {}

    [[nodiscard]] std::uint8_t type() const noexcept { return type_; }
    [[nodiscard]] const SessionId& session_id() const noexcept { return session_id_; }
    [[nodiscard]] std::uint64_t seq_num() const noexcept { return seq_num_; }
    [[nodiscard]] std::uint16_t length() const noexcept { return length_; }

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<PacketHeader> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const PacketHeader& other) const noexcept {
        return type_ == other.type_ && session_id_ == other.session_id_ &&
               seq_num_ == other.seq_num_ && length_ == other.length_;
    }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<PacketHeader> from_json(const nlohmann::json& j);

private:
    std::uint8_t type_ = 0;
    SessionId session_id_{};
    std::uint64_t seq_num_ = 0;
    std::uint16_t length_ = 0;
};

// ── 20. Packet ───────────────────────────────────────────────────────────────
class Packet {
public:
    Packet() = default;
    Packet(PacketHeader header, Bytes payload)
        : header_(header), payload_(std::move(payload)) {}

    [[nodiscard]] const PacketHeader& header() const noexcept { return header_; }
    [[nodiscard]] const Bytes& payload() const noexcept { return payload_; }

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<Packet> deserialize(ByteSpan bytes);
    [[nodiscard]] VoidResult validate() const;
    bool operator==(const Packet& other) const noexcept {
        return header_ == other.header_ && payload_ == other.payload_;
    }

    [[nodiscard]] nlohmann::json to_json() const;
    [[nodiscard]] static Result<Packet> from_json(const nlohmann::json& j);

private:
    PacketHeader header_;
    Bytes payload_;
};

} // namespace uav_pqc::types
