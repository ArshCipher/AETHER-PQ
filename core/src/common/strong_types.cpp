// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/common/strong_types.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace uav_pqc::types {

namespace {

// Helper to write uint16_t in big-endian
void write_u16_be(std::byte* dst, std::uint16_t val) noexcept {
    dst[0] = static_cast<std::byte>((val >> 8) & 0xFF);
    dst[1] = static_cast<std::byte>(val & 0xFF);
}

// Helper to read uint16_t in big-endian
std::uint16_t read_u16_be(const std::byte* src) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint8_t>(src[0]) << 8) | static_cast<std::uint8_t>(src[1]));
}

// Helper to write uint32_t in big-endian
void write_u32_be(std::byte* dst, std::uint32_t val) noexcept {
    dst[0] = static_cast<std::byte>((val >> 24) & 0xFF);
    dst[1] = static_cast<std::byte>((val >> 16) & 0xFF);
    dst[2] = static_cast<std::byte>((val >> 8) & 0xFF);
    dst[3] = static_cast<std::byte>(val & 0xFF);
}

// Helper to read uint32_t in big-endian
std::uint32_t read_u32_be(const std::byte* src) noexcept {
    return (static_cast<std::uint32_t>(src[0]) << 24) |
           (static_cast<std::uint32_t>(src[1]) << 16) |
           (static_cast<std::uint32_t>(src[2]) << 8) |
           static_cast<std::uint32_t>(src[3]);
}

// Helper to write double as bytes
void write_double(std::byte* dst, double val) noexcept {
    std::memcpy(dst, &val, sizeof(double));
}

// Helper to read double from bytes
double read_double(const std::byte* src) noexcept {
    double val;
    std::memcpy(&val, src, sizeof(double));
    return val;
}

} // namespace

// ── 1. Timestamp ─────────────────────────────────────────────────────────────
Bytes Timestamp::serialize() const {
    Bytes b(8);
    write_u64_be(MutableByteSpan{b.data(), 8}, val_);
    return b;
}

Result<Timestamp> Timestamp::deserialize(ByteSpan bytes) {
    if (bytes.size() < 8) {
        return err<Timestamp>(ErrorCode::InvalidArgument, "Truncated timestamp bytes");
    }
    return ok<Timestamp>(Timestamp(read_u64_be(bytes)));
}

VoidResult Timestamp::validate() const {
    return ok();
}

nlohmann::json Timestamp::to_json() const {
    return nlohmann::json(val_);
}

Result<Timestamp> Timestamp::from_json(const nlohmann::json& j) {
    if (!j.is_number_integer()) {
        return err<Timestamp>(ErrorCode::InvalidArgument, "Expected integer for Timestamp");
    }
    return ok<Timestamp>(Timestamp(j.get<uav_pqc::Timestamp>()));
}


// ── 2. NodeID ────────────────────────────────────────────────────────────────
Bytes NodeID::serialize() const {
    return Bytes(val_.begin(), val_.end());
}

Result<NodeID> NodeID::deserialize(ByteSpan bytes) {
    if (bytes.size() < 32) {
        return err<NodeID>(ErrorCode::InvalidArgument, "Truncated NodeID bytes");
    }
    NodeId nid;
    std::copy_n(bytes.data(), 32, nid.data());
    return ok<NodeID>(NodeID(nid));
}

VoidResult NodeID::validate() const {
    return ok();
}

nlohmann::json NodeID::to_json() const {
    return nlohmann::json(to_hex(val_));
}

Result<NodeID> NodeID::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<NodeID>(ErrorCode::InvalidArgument, "Expected hex string for NodeID");
    }
    auto hex_str = j.get<std::string>();
    auto b = from_hex(hex_str);
    if (b.size() != 32) {
        return err<NodeID>(ErrorCode::InvalidArgument, "NodeID hex string must represent 32 bytes");
    }
    NodeId nid;
    std::copy(b.begin(), b.end(), nid.begin());
    return ok<NodeID>(NodeID(nid));
}


// ── 3. SessionID ─────────────────────────────────────────────────────────────
Bytes SessionID::serialize() const {
    return Bytes(val_.begin(), val_.end());
}

Result<SessionID> SessionID::deserialize(ByteSpan bytes) {
    if (bytes.size() < 16) {
        return err<SessionID>(ErrorCode::InvalidArgument, "Truncated SessionID bytes");
    }
    SessionId sid;
    std::copy_n(bytes.data(), 16, sid.data());
    return ok<SessionID>(SessionID(sid));
}

VoidResult SessionID::validate() const {
    return ok();
}

nlohmann::json SessionID::to_json() const {
    return nlohmann::json(to_hex(val_));
}

Result<SessionID> SessionID::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<SessionID>(ErrorCode::InvalidArgument, "Expected hex string for SessionID");
    }
    auto hex_str = j.get<std::string>();
    auto b = from_hex(hex_str);
    if (b.size() != 16) {
        return err<SessionID>(ErrorCode::InvalidArgument, "SessionID hex string must represent 16 bytes");
    }
    SessionId sid;
    std::copy(b.begin(), b.end(), sid.begin());
    return ok<SessionID>(SessionID(sid));
}


// ── 4. Nonce ─────────────────────────────────────────────────────────────────
Bytes Nonce::serialize() const {
    return Bytes(val_.begin(), val_.end());
}

Result<Nonce> Nonce::deserialize(ByteSpan bytes) {
    if (bytes.size() < 12) {
        return err<Nonce>(ErrorCode::InvalidArgument, "Truncated Nonce bytes");
    }
    std::array<std::byte, 12> val;
    std::copy_n(bytes.data(), 12, val.data());
    return ok<Nonce>(Nonce(val));
}

VoidResult Nonce::validate() const {
    return ok();
}

nlohmann::json Nonce::to_json() const {
    return nlohmann::json(to_hex(val_));
}

Result<Nonce> Nonce::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<Nonce>(ErrorCode::InvalidArgument, "Expected hex string for Nonce");
    }
    auto hex_str = j.get<std::string>();
    auto b = from_hex(hex_str);
    if (b.size() != 12) {
        return err<Nonce>(ErrorCode::InvalidArgument, "Nonce hex string must represent 12 bytes");
    }
    std::array<std::byte, 12> val;
    std::copy(b.begin(), b.end(), val.begin());
    return ok<Nonce>(Nonce(val));
}


// ── 5. OperatingMode ─────────────────────────────────────────────────────────
Bytes OperatingMode::serialize() const {
    Bytes b(1);
    b[0] = static_cast<std::byte>(val_);
    return b;
}

Result<OperatingMode> OperatingMode::deserialize(ByteSpan bytes) {
    if (bytes.empty()) {
        return err<OperatingMode>(ErrorCode::InvalidArgument, "Empty bytes for OperatingMode");
    }
    auto val = static_cast<protocol::OperatingMode>(bytes[0]);
    return ok<OperatingMode>(OperatingMode(val));
}

VoidResult OperatingMode::validate() const {
    if (val_ != protocol::OperatingMode::Classical &&
        val_ != protocol::OperatingMode::Transition &&
        val_ != protocol::OperatingMode::Hybrid &&
        val_ != protocol::OperatingMode::PqcOnly) {
        return err(ErrorCode::PolicyViolation, "Invalid OperatingMode value");
    }
    return ok();
}

nlohmann::json OperatingMode::to_json() const {
    switch (val_) {
        case protocol::OperatingMode::Classical: return "classical";
        case protocol::OperatingMode::Transition: return "transition";
        case protocol::OperatingMode::Hybrid: return "hybrid";
        case protocol::OperatingMode::PqcOnly: return "pqc-only";
    }
    return "unknown";
}

Result<OperatingMode> OperatingMode::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<OperatingMode>(ErrorCode::InvalidArgument, "Expected string for OperatingMode");
    }
    auto str = j.get<std::string>();
    if (str == "classical") return ok<OperatingMode>(OperatingMode(protocol::OperatingMode::Classical));
    if (str == "transition") return ok<OperatingMode>(OperatingMode(protocol::OperatingMode::Transition));
    if (str == "hybrid") return ok<OperatingMode>(OperatingMode(protocol::OperatingMode::Hybrid));
    if (str == "pqc-only") return ok<OperatingMode>(OperatingMode(protocol::OperatingMode::PqcOnly));
    return err<OperatingMode>(ErrorCode::InvalidArgument, "Unknown OperatingMode name: " + str);
}


// ── 6. CryptoProfile ─────────────────────────────────────────────────────────
Bytes CryptoProfile::serialize() const {
    Bytes b(1);
    b[0] = static_cast<std::byte>(val_);
    return b;
}

Result<CryptoProfile> CryptoProfile::deserialize(ByteSpan bytes) {
    if (bytes.empty()) {
        return err<CryptoProfile>(ErrorCode::InvalidArgument, "Empty bytes for CryptoProfile");
    }
    auto val = static_cast<policy::CryptographicProfile>(bytes[0]);
    return ok<CryptoProfile>(CryptoProfile(val));
}

VoidResult CryptoProfile::validate() const {
    if (val_ != policy::CryptographicProfile::Lightweight &&
        val_ != policy::CryptographicProfile::Standard &&
        val_ != policy::CryptographicProfile::Hardened) {
        return err(ErrorCode::PolicyViolation, "Invalid CryptoProfile value");
    }
    return ok();
}

nlohmann::json CryptoProfile::to_json() const {
    switch (val_) {
        case policy::CryptographicProfile::Lightweight: return "lightweight";
        case policy::CryptographicProfile::Standard: return "standard";
        case policy::CryptographicProfile::Hardened: return "hardened";
    }
    return "unknown";
}

Result<CryptoProfile> CryptoProfile::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<CryptoProfile>(ErrorCode::InvalidArgument, "Expected string for CryptoProfile");
    }
    auto str = j.get<std::string>();
    if (str == "lightweight") return ok<CryptoProfile>(CryptoProfile(policy::CryptographicProfile::Lightweight));
    if (str == "standard") return ok<CryptoProfile>(CryptoProfile(policy::CryptographicProfile::Standard));
    if (str == "hardened") return ok<CryptoProfile>(CryptoProfile(policy::CryptographicProfile::Hardened));
    return err<CryptoProfile>(ErrorCode::InvalidArgument, "Unknown CryptoProfile name: " + str);
}


// ── 7. CipherSuite ───────────────────────────────────────────────────────────
Bytes CipherSuite::serialize() const {
    Bytes b(17);
    b[0] = static_cast<std::byte>(val_.mode);
    b[1] = static_cast<std::byte>(val_.kem_level);
    b[2] = static_cast<std::byte>(val_.dsa_level);
    b[3] = static_cast<std::byte>(val_.aead_algorithm);
    b[4] = static_cast<std::byte>(val_.hkdf_hash);
    write_u32_be(b.data() + 5, val_.max_session_seconds);
    write_u64_be(MutableByteSpan{b.data() + 9, 8}, val_.max_messages_per_key);
    return b;
}

Result<CipherSuite> CipherSuite::deserialize(ByteSpan bytes) {
    if (bytes.size() < 17) {
        return err<CipherSuite>(ErrorCode::InvalidArgument, "Truncated CipherSuite bytes");
    }
    protocol::CipherSuite val;
    val.mode = static_cast<protocol::OperatingMode>(bytes[0]);
    val.kem_level = static_cast<crypto::MlKem::Level>(bytes[1]);
    val.dsa_level = static_cast<crypto::MlDsa::Level>(bytes[2]);
    val.aead_algorithm = static_cast<protocol::AeadAlgorithm>(bytes[3]);
    val.hkdf_hash = static_cast<crypto::HkdfHash>(bytes[4]);
    val.max_session_seconds = read_u32_be(bytes.data() + 5);
    val.max_messages_per_key = read_u64_be(bytes.subspan(9, 8));
    return ok<CipherSuite>(CipherSuite(val));
}

VoidResult CipherSuite::validate() const {
    return ok();
}

bool CipherSuite::operator==(const CipherSuite& other) const noexcept {
    return val_ == other.val_;
}

nlohmann::json CipherSuite::to_json() const {
    nlohmann::json j;
    j["mode"] = static_cast<std::uint8_t>(val_.mode);
    j["kem_level"] = static_cast<std::uint8_t>(val_.kem_level);
    j["dsa_level"] = static_cast<std::uint8_t>(val_.dsa_level);
    j["aead_algorithm"] = static_cast<std::uint8_t>(val_.aead_algorithm);
    j["hkdf_hash"] = static_cast<std::uint8_t>(val_.hkdf_hash);
    j["max_session_seconds"] = val_.max_session_seconds;
    j["max_messages_per_key"] = val_.max_messages_per_key;
    return j;
}

Result<CipherSuite> CipherSuite::from_json(const nlohmann::json& j) {
    try {
        protocol::CipherSuite val;
        val.mode = static_cast<protocol::OperatingMode>(j["mode"].get<std::uint8_t>());
        val.kem_level = static_cast<crypto::MlKem::Level>(j["kem_level"].get<std::uint8_t>());
        val.dsa_level = static_cast<crypto::MlDsa::Level>(j["dsa_level"].get<std::uint8_t>());
        val.aead_algorithm = static_cast<protocol::AeadAlgorithm>(j["aead_algorithm"].get<std::uint8_t>());
        val.hkdf_hash = static_cast<crypto::HkdfHash>(j["hkdf_hash"].get<std::uint8_t>());
        val.max_session_seconds = j["max_session_seconds"].get<std::uint32_t>();
        val.max_messages_per_key = j["max_messages_per_key"].get<std::uint64_t>();
        return ok<CipherSuite>(CipherSuite(val));
    } catch (const std::exception& e) {
        return err<CipherSuite>(ErrorCode::InvalidArgument, std::string("CipherSuite from_json failed: ") + e.what());
    }
}


// ── 8. ProtocolVersion ───────────────────────────────────────────────────────
Bytes ProtocolVersion::serialize() const {
    Bytes b(2);
    b[0] = static_cast<std::byte>(major_);
    b[1] = static_cast<std::byte>(minor_);
    return b;
}

Result<ProtocolVersion> ProtocolVersion::deserialize(ByteSpan bytes) {
    if (bytes.size() < 2) {
        return err<ProtocolVersion>(ErrorCode::InvalidArgument, "Truncated ProtocolVersion bytes");
    }
    return ok<ProtocolVersion>(ProtocolVersion(static_cast<std::uint8_t>(bytes[0]), static_cast<std::uint8_t>(bytes[1])));
}

VoidResult ProtocolVersion::validate() const {
    if (major_ == 0) return err(ErrorCode::PolicyViolation, "Major version cannot be zero");
    return ok();
}

nlohmann::json ProtocolVersion::to_json() const {
    return nlohmann::json(std::to_string(major_) + "." + std::to_string(minor_));
}

Result<ProtocolVersion> ProtocolVersion::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<ProtocolVersion>(ErrorCode::InvalidArgument, "Expected string for ProtocolVersion");
    }
    auto str = j.get<std::string>();
    auto dot = str.find('.');
    if (dot == std::string::npos) {
        return err<ProtocolVersion>(ErrorCode::InvalidArgument, "Invalid version format: " + str);
    }
    try {
        auto major = static_cast<std::uint8_t>(std::stoul(str.substr(0, dot)));
        auto minor = static_cast<std::uint8_t>(std::stoul(str.substr(dot + 1)));
        return ok<ProtocolVersion>(ProtocolVersion(major, minor));
    } catch (...) {
        return err<ProtocolVersion>(ErrorCode::InvalidArgument, "Invalid version numbers: " + str);
    }
}


// ── 9. MissionType ───────────────────────────────────────────────────────────
Bytes MissionType::serialize() const {
    Bytes b(1);
    b[0] = static_cast<std::byte>(val_);
    return b;
}

Result<MissionType> MissionType::deserialize(ByteSpan bytes) {
    if (bytes.empty()) {
        return err<MissionType>(ErrorCode::InvalidArgument, "Empty bytes for MissionType");
    }
    return ok<MissionType>(MissionType(static_cast<Type>(bytes[0])));
}

VoidResult MissionType::validate() const {
    if (val_ != Type::Civilian && val_ != Type::Commercial && val_ != Type::Military) {
        return err(ErrorCode::PolicyViolation, "Invalid MissionType value");
    }
    return ok();
}

nlohmann::json MissionType::to_json() const {
    switch (val_) {
        case Type::Civilian: return "civilian";
        case Type::Commercial: return "commercial";
        case Type::Military: return "military";
    }
    return "unknown";
}

Result<MissionType> MissionType::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<MissionType>(ErrorCode::InvalidArgument, "Expected string for MissionType");
    }
    auto str = j.get<std::string>();
    if (str == "civilian") return ok<MissionType>(MissionType(Type::Civilian));
    if (str == "commercial") return ok<MissionType>(MissionType(Type::Commercial));
    if (str == "military") return ok<MissionType>(MissionType(Type::Military));
    return err<MissionType>(ErrorCode::InvalidArgument, "Unknown MissionType: " + str);
}


// ── 10. BatteryStatus ────────────────────────────────────────────────────────
Bytes BatteryStatus::serialize() const {
    Bytes b(8);
    write_double(b.data(), percent_);
    return b;
}

Result<BatteryStatus> BatteryStatus::deserialize(ByteSpan bytes) {
    if (bytes.size() < 8) {
        return err<BatteryStatus>(ErrorCode::InvalidArgument, "Truncated BatteryStatus bytes");
    }
    return ok<BatteryStatus>(BatteryStatus(read_double(bytes.data())));
}

VoidResult BatteryStatus::validate() const {
    if (percent_ < 0.0 || percent_ > 100.0) {
        return err(ErrorCode::PolicyViolation, "Battery percent must be between 0 and 100");
    }
    return ok();
}

nlohmann::json BatteryStatus::to_json() const {
    return nlohmann::json(percent_);
}

Result<BatteryStatus> BatteryStatus::from_json(const nlohmann::json& j) {
    if (!j.is_number()) {
        return err<BatteryStatus>(ErrorCode::InvalidArgument, "Expected number for BatteryStatus");
    }
    return ok<BatteryStatus>(BatteryStatus(j.get<double>()));
}


// ── 11. NetworkMetrics ───────────────────────────────────────────────────────
Bytes NetworkMetrics::serialize() const {
    Bytes b(16);
    write_double(b.data(), snr_db_);
    write_double(b.data() + 8, loss_rate_);
    return b;
}

Result<NetworkMetrics> NetworkMetrics::deserialize(ByteSpan bytes) {
    if (bytes.size() < 16) {
        return err<NetworkMetrics>(ErrorCode::InvalidArgument, "Truncated NetworkMetrics bytes");
    }
    double snr = read_double(bytes.data());
    double loss = read_double(bytes.data() + 8);
    return ok<NetworkMetrics>(NetworkMetrics(snr, loss));
}

VoidResult NetworkMetrics::validate() const {
    if (loss_rate_ < 0.0 || loss_rate_ > 1.0) {
        return err(ErrorCode::PolicyViolation, "Loss rate must be between 0 and 1");
    }
    return ok();
}

nlohmann::json NetworkMetrics::to_json() const {
    nlohmann::json j;
    j["snr_db"] = snr_db_;
    j["loss_rate"] = loss_rate_;
    return j;
}

Result<NetworkMetrics> NetworkMetrics::from_json(const nlohmann::json& j) {
    try {
        double snr = j["snr_db"].get<double>();
        double loss = j["loss_rate"].get<double>();
        return ok<NetworkMetrics>(NetworkMetrics(snr, loss));
    } catch (...) {
        return err<NetworkMetrics>(ErrorCode::InvalidArgument, "Invalid NetworkMetrics JSON");
    }
}


// ── 12. Certificate ──────────────────────────────────────────────────────────
Bytes Certificate::serialize() const {
    return val_.to_der();
}

Result<Certificate> Certificate::deserialize(ByteSpan bytes) {
    auto cert_r = identity::Certificate::from_der(Bytes(bytes.begin(), bytes.end()));
    if (!cert_r) return err<Certificate>(cert_r.error());
    return ok<Certificate>(Certificate(cert_r.value()));
}

VoidResult Certificate::validate() const {
    return ok();
}

bool Certificate::operator==(const Certificate& other) const noexcept {
    return val_.to_der() == other.val_.to_der();
}

nlohmann::json Certificate::to_json() const {
    return nlohmann::json(to_hex(val_.to_der()));
}

Result<Certificate> Certificate::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<Certificate>(ErrorCode::InvalidArgument, "Expected string for Certificate DER hex");
    }
    auto hex_str = j.get<std::string>();
    auto b = from_hex(hex_str);
    auto cert_r = identity::Certificate::from_der(b);
    if (!cert_r) return err<Certificate>(cert_r.error());
    return ok<Certificate>(Certificate(cert_r.value()));
}


// ── 13. CertificateChain ─────────────────────────────────────────────────────
Bytes CertificateChain::serialize() const {
    Bytes b;
    // Total count of certificates
    b.push_back(static_cast<std::byte>((val_.size() >> 8) & 0xFF));
    b.push_back(static_cast<std::byte>(val_.size() & 0xFF));
    for (const auto& cert : val_) {
        Bytes der = cert.to_der();
        // 2-byte DER length
        b.push_back(static_cast<std::byte>((der.size() >> 8) & 0xFF));
        b.push_back(static_cast<std::byte>(der.size() & 0xFF));
        b.insert(b.end(), der.begin(), der.end());
    }
    return b;
}

Result<CertificateChain> CertificateChain::deserialize(ByteSpan bytes) {
    if (bytes.size() < 2) {
        return err<CertificateChain>(ErrorCode::InvalidArgument, "Truncated chain count");
    }
    std::uint16_t count = read_u16_be(bytes.data());
    const std::byte* ptr = bytes.data() + 2;
    const std::byte* end = bytes.data() + bytes.size();

    std::vector<identity::Certificate> parsed;
    for (std::uint16_t i = 0; i < count; ++i) {
        if (ptr + 2 > end) {
            return err<CertificateChain>(ErrorCode::InvalidArgument, "Truncated cert length");
        }
        std::uint16_t len = read_u16_be(ptr);
        ptr += 2;
        if (ptr + len > end) {
            return err<CertificateChain>(ErrorCode::InvalidArgument, "Truncated cert DER");
        }
        auto cert_r = identity::Certificate::from_der(Bytes(ptr, ptr + len));
        if (!cert_r) return err<CertificateChain>(cert_r.error());
        parsed.push_back(cert_r.value());
        ptr += len;
    }
    return ok<CertificateChain>(CertificateChain(parsed));
}

VoidResult CertificateChain::validate() const {
    if (val_.empty()) return err(ErrorCode::PolicyViolation, "CertificateChain cannot be empty");
    return ok();
}

bool CertificateChain::operator==(const CertificateChain& other) const noexcept {
    if (val_.size() != other.val_.size()) return false;
    for (std::size_t i = 0; i < val_.size(); ++i) {
        if (val_[i].to_der() != other.val_[i].to_der()) return false;
    }
    return true;
}

nlohmann::json CertificateChain::to_json() const {
    nlohmann::json j = nlohmann::json::array();
    for (const auto& cert : val_) {
        j.push_back(to_hex(cert.to_der()));
    }
    return j;
}

Result<CertificateChain> CertificateChain::from_json(const nlohmann::json& j) {
    if (!j.is_array()) {
        return err<CertificateChain>(ErrorCode::InvalidArgument, "Expected JSON array for CertificateChain");
    }
    std::vector<identity::Certificate> parsed;
    for (const auto& item : j) {
        if (!item.is_string()) {
            return err<CertificateChain>(ErrorCode::InvalidArgument, "Chain element must be a string");
        }
        auto b = from_hex(item.get<std::string>());
        auto cert_r = identity::Certificate::from_der(b);
        if (!cert_r) return err<CertificateChain>(cert_r.error());
        parsed.push_back(cert_r.value());
    }
    return ok<CertificateChain>(CertificateChain(parsed));
}


// ── 14. CertificateRevocation ────────────────────────────────────────────────
Bytes CertificateRevocation::serialize() const {
    Bytes b(40);
    std::copy_n(target_.data(), 32, b.data());
    write_u64_be(MutableByteSpan{b.data() + 32, 8}, revoked_at_);
    return b;
}

Result<CertificateRevocation> CertificateRevocation::deserialize(ByteSpan bytes) {
    if (bytes.size() < 40) {
        return err<CertificateRevocation>(ErrorCode::InvalidArgument, "Truncated CertificateRevocation bytes");
    }
    NodeId target;
    std::copy_n(bytes.data(), 32, target.data());
    uav_pqc::Timestamp ts = read_u64_be(bytes.subspan(32, 8));
    return ok<CertificateRevocation>(CertificateRevocation(target, ts));
}

VoidResult CertificateRevocation::validate() const {
    return ok();
}

nlohmann::json CertificateRevocation::to_json() const {
    nlohmann::json j;
    j["target"] = to_hex(target_);
    j["revoked_at"] = revoked_at_;
    return j;
}

Result<CertificateRevocation> CertificateRevocation::from_json(const nlohmann::json& j) {
    try {
        auto hex_str = j["target"].get<std::string>();
        auto b = from_hex(hex_str);
        NodeId target;
        std::copy(b.begin(), b.end(), target.begin());
        uav_pqc::Timestamp ts = j["revoked_at"].get<uav_pqc::Timestamp>();
        return ok<CertificateRevocation>(CertificateRevocation(target, ts));
    } catch (...) {
        return err<CertificateRevocation>(ErrorCode::InvalidArgument, "Invalid CertificateRevocation JSON");
    }
}


// ── 15. TreeNode ─────────────────────────────────────────────────────────────
Bytes TreeNode::serialize() const {
    Bytes b(6);
    write_u32_be(b.data(), index_);
    write_u16_be(b.data() + 4, static_cast<std::uint16_t>(key_.data.size()));
    b.insert(b.end(), key_.data.begin(), key_.data.end());
    return b;
}

Result<TreeNode> TreeNode::deserialize(ByteSpan bytes) {
    if (bytes.size() < 6) {
        return err<TreeNode>(ErrorCode::InvalidArgument, "Truncated TreeNode bytes");
    }
    std::uint32_t idx = read_u32_be(bytes.data());
    std::uint16_t len = read_u16_be(bytes.data() + 4);
    if (bytes.size() < static_cast<std::size_t>(6 + len)) {
        return err<TreeNode>(ErrorCode::InvalidArgument, "Truncated TreeNode key bytes");
    }
    crypto::KemPublicKey pk;
    pk.data.assign(bytes.data() + 6, bytes.data() + 6 + len);
    return ok<TreeNode>(TreeNode(idx, pk));
}

VoidResult TreeNode::validate() const {
    return ok();
}

bool TreeNode::operator==(const TreeNode& other) const noexcept {
    return index_ == other.index_ && key_.data == other.key_.data;
}

nlohmann::json TreeNode::to_json() const {
    nlohmann::json j;
    j["index"] = index_;
    j["key"] = to_hex(key_.data);
    return j;
}

Result<TreeNode> TreeNode::from_json(const nlohmann::json& j) {
    try {
        std::uint32_t idx = j["index"].get<std::uint32_t>();
        auto hex_str = j["key"].get<std::string>();
        crypto::KemPublicKey pk;
        pk.data = from_hex(hex_str);
        return ok<TreeNode>(TreeNode(idx, pk));
    } catch (...) {
        return err<TreeNode>(ErrorCode::InvalidArgument, "Invalid TreeNode JSON");
    }
}


// ── 16. PairwiseKey ──────────────────────────────────────────────────────────
Bytes PairwiseKey::serialize() const {
    return Bytes(val_.data(), val_.data() + val_.size());
}

Result<PairwiseKey> PairwiseKey::deserialize(ByteSpan bytes) {
    SecureBytes sb(Bytes(bytes.begin(), bytes.end()));
    return ok<PairwiseKey>(PairwiseKey(std::move(sb)));
}

VoidResult PairwiseKey::validate() const {
    return ok();
}

bool PairwiseKey::operator==(const PairwiseKey& other) const noexcept {
    return constant_time_equal(val_.span(), other.val_.span());
}

nlohmann::json PairwiseKey::to_json() const {
    return nlohmann::json(to_hex(val_.span()));
}

Result<PairwiseKey> PairwiseKey::from_json(const nlohmann::json& j) {
    if (!j.is_string()) {
        return err<PairwiseKey>(ErrorCode::InvalidArgument, "Expected string for PairwiseKey hex");
    }
    auto hex_str = j.get<std::string>();
    SecureBytes sb(from_hex(hex_str));
    return ok<PairwiseKey>(PairwiseKey(std::move(sb)));
}


// ── 17. GroupKey ─────────────────────────────────────────────────────────────
Bytes GroupKey::serialize() const {
    Bytes b;
    if (!val_.has_value()) return b;
    // epoch (8)
    b.resize(8);
    write_u64_be(MutableByteSpan{b.data(), 8}, val_->epoch());
    // algorithm (1)
    b.push_back(static_cast<std::byte>(val_->algorithm()));
    // issued_ms (8)
    std::size_t offset = b.size();
    b.resize(offset + 8);
    write_u64_be(MutableByteSpan{b.data() + offset, 8}, val_->issued_ms());
    // expiry_ms (8)
    offset = b.size();
    b.resize(offset + 8);
    write_u64_be(MutableByteSpan{b.data() + offset, 8}, val_->expiry_ms());
    // key bytes length (2)
    crypto::AeadKey ak = val_->make_aead_key();
    offset = b.size();
    b.resize(offset + 2);
    write_u16_be(b.data() + offset, static_cast<std::uint16_t>(ak.size()));
    // key bytes
    b.insert(b.end(), ak.span().begin(), ak.span().end());

    return b;
}

Result<GroupKey> GroupKey::deserialize(ByteSpan bytes) {
    if (bytes.size() < 27) {
        return err<GroupKey>(ErrorCode::InvalidArgument, "Truncated GroupKey bytes");
    }
    GroupEpoch epoch = read_u64_be(bytes.subspan(0, 8));
    auto algo = static_cast<protocol::AeadAlgorithm>(bytes[8]);
    uav_pqc::Timestamp issued = read_u64_be(bytes.subspan(9, 8));
    uav_pqc::Timestamp expiry = read_u64_be(bytes.subspan(17, 8));
    std::uint16_t key_len = read_u16_be(bytes.data() + 25);
    if (bytes.size() < static_cast<std::size_t>(27 + key_len)) {
        return err<GroupKey>(ErrorCode::InvalidArgument, "Truncated GroupKey key bytes");
    }
    SecureBytes kb(Bytes(bytes.data() + 27, bytes.data() + 27 + key_len));
    group::GroupKey gk(epoch, std::move(kb), algo, issued, expiry);
    return ok<GroupKey>(GroupKey(std::move(gk)));
}

VoidResult GroupKey::validate() const {
    if (!val_.has_value()) {
        return err(ErrorCode::PolicyViolation, "GroupKey is empty");
    }
    return ok();
}

bool GroupKey::operator==(const GroupKey& other) const noexcept {
    if (val_.has_value() != other.val_.has_value()) return false;
    if (!val_.has_value()) return true;
    return val_->epoch() == other.val_->epoch() &&
           val_->algorithm() == other.val_->algorithm() &&
           val_->issued_ms() == other.val_->issued_ms() &&
           val_->expiry_ms() == other.val_->expiry_ms() &&
           constant_time_equal(val_->make_aead_key().span(), other.val_->make_aead_key().span());
}

nlohmann::json GroupKey::to_json() const {
    nlohmann::json j;
    if (!val_.has_value()) return j;
    j["epoch"] = val_->epoch();
    j["algorithm"] = static_cast<std::uint8_t>(val_->algorithm());
    j["issued_ms"] = val_->issued_ms();
    j["expiry_ms"] = val_->expiry_ms();
    j["key"] = to_hex(val_->make_aead_key().span());
    return j;
}

Result<GroupKey> GroupKey::from_json(const nlohmann::json& j) {
    try {
        GroupEpoch epoch = j["epoch"].get<GroupEpoch>();
        auto algo = static_cast<protocol::AeadAlgorithm>(j["algorithm"].get<std::uint8_t>());
        uav_pqc::Timestamp issued = j["issued_ms"].get<uav_pqc::Timestamp>();
        uav_pqc::Timestamp expiry = j["expiry_ms"].get<uav_pqc::Timestamp>();
        auto hex_str = j["key"].get<std::string>();
        SecureBytes kb(from_hex(hex_str));
        group::GroupKey gk(epoch, std::move(kb), algo, issued, expiry);
        return ok<GroupKey>(GroupKey(std::move(gk)));
    } catch (...) {
        return err<GroupKey>(ErrorCode::InvalidArgument, "Invalid GroupKey JSON");
    }
}


// ── 18. Session ──────────────────────────────────────────────────────────────
Bytes Session::serialize() const {
    Bytes b;
    if (!val_.has_value()) return b;
    // session_id (16)
    b.insert(b.end(), val_->id_.begin(), val_->id_.end());
    // peer_node_id (32)
    b.insert(b.end(), val_->peer_node_id_.begin(), val_->peer_node_id_.end());
    // suite (17)
    CipherSuite cs_wrap(val_->suite_);
    Bytes cs_bytes = cs_wrap.serialize();
    b.insert(b.end(), cs_bytes.begin(), cs_bytes.end());
    // expiry_ms (8)
    std::size_t offset = b.size();
    b.resize(offset + 8);
    write_u64_be(MutableByteSpan{b.data() + offset, 8}, val_->expiry_ms_);
    // send_key (2 + len)
    offset = b.size();
    b.resize(offset + 2);
    write_u16_be(b.data() + offset, static_cast<std::uint16_t>(val_->send_key_.size()));
    b.insert(b.end(), val_->send_key_.span().begin(), val_->send_key_.span().end());
    // recv_key (2 + len)
    offset = b.size();
    b.resize(offset + 2);
    write_u16_be(b.data() + offset, static_cast<std::uint16_t>(val_->recv_key_.size()));
    b.insert(b.end(), val_->recv_key_.span().begin(), val_->recv_key_.span().end());
    // send_nonces: prefix (4), counter (8), max_messages (8)
    b.insert(b.end(), val_->send_nonces_.prefix_.begin(), val_->send_nonces_.prefix_.end());
    offset = b.size();
    b.resize(offset + 16);
    write_u64_be(MutableByteSpan{b.data() + offset, 8}, val_->send_nonces_.counter_);
    write_u64_be(MutableByteSpan{b.data() + offset + 8, 8}, val_->send_nonces_.max_messages_);
    // recv_nonces: prefix (4), counter (8), max_messages (8)
    b.insert(b.end(), val_->recv_nonces_.prefix_.begin(), val_->recv_nonces_.prefix_.end());
    offset = b.size();
    b.resize(offset + 16);
    write_u64_be(MutableByteSpan{b.data() + offset, 8}, val_->recv_nonces_.counter_);
    write_u64_be(MutableByteSpan{b.data() + offset + 8, 8}, val_->recv_nonces_.max_messages_);
    // stats: sent (8), received (8), enc (8), dec (8)
    offset = b.size();
    b.resize(offset + 32);
    write_u64_be(MutableByteSpan{b.data() + offset, 8}, val_->stats_.messages_sent);
    write_u64_be(MutableByteSpan{b.data() + offset + 8, 8}, val_->stats_.messages_received);
    write_u64_be(MutableByteSpan{b.data() + offset + 16, 8}, val_->stats_.bytes_encrypted);
    write_u64_be(MutableByteSpan{b.data() + offset + 24, 8}, val_->stats_.bytes_decrypted);

    return b;
}

Result<Session> Session::deserialize(ByteSpan bytes) {
    if (bytes.size() < 147) {
        return err<Session>(ErrorCode::InvalidArgument, "Truncated Session bytes");
    }
    const std::byte* ptr = bytes.data();
    SessionId sid;
    std::copy_n(ptr, 16, sid.data());
    ptr += 16;
    NodeId nid;
    std::copy_n(ptr, 32, nid.data());
    ptr += 32;

    auto cs_r = CipherSuite::deserialize(ByteSpan{ptr, 17});
    if (!cs_r) return err<Session>(cs_r.error());
    protocol::CipherSuite cs = cs_r.value().value();
    ptr += 17;

    uav_pqc::Timestamp expiry = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;

    std::uint16_t send_len = read_u16_be(ptr);
    ptr += 2;
    crypto::AeadKey send_key = crypto::AeadKey::from_bytes(ByteSpan{ptr, send_len});
    ptr += send_len;

    std::uint16_t recv_len = read_u16_be(ptr);
    ptr += 2;
    crypto::AeadKey recv_key = crypto::AeadKey::from_bytes(ByteSpan{ptr, recv_len});
    ptr += recv_len;

    std::array<std::byte, 4> send_prefix;
    std::copy_n(ptr, 4, send_prefix.data());
    ptr += 4;
    std::uint64_t send_ctr = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;
    std::uint64_t send_max = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;

    std::array<std::byte, 4> recv_prefix;
    std::copy_n(ptr, 4, recv_prefix.data());
    ptr += 4;
    std::uint64_t recv_ctr = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;
    std::uint64_t recv_max = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;

    session::SessionStats stats;
    stats.messages_sent = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;
    stats.messages_received = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;
    stats.bytes_encrypted = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;
    stats.bytes_decrypted = read_u64_be(ByteSpan{ptr, 8});

    std::array<std::byte, 4> send_pref_arr = {send_prefix[0], send_prefix[1], send_prefix[2], send_prefix[3]};
    std::array<std::byte, 4> recv_pref_arr = {recv_prefix[0], recv_prefix[1], recv_prefix[2], recv_prefix[3]};

    session::Session sess(sid, nid, cs, std::move(send_key), std::move(recv_key), send_pref_arr, recv_pref_arr, expiry);
    sess.send_nonces_.counter_ = send_ctr;
    sess.send_nonces_.max_messages_ = send_max;
    sess.recv_nonces_.counter_ = recv_ctr;
    sess.recv_nonces_.max_messages_ = recv_max;
    sess.stats_ = stats;

    return ok<Session>(Session(std::move(sess)));
}

VoidResult Session::validate() const {
    if (!val_.has_value()) {
        return err(ErrorCode::PolicyViolation, "Session is empty");
    }
    return ok();
}

bool Session::operator==(const Session& other) const noexcept {
    if (val_.has_value() != other.val_.has_value()) return false;
    if (!val_.has_value()) return true;
    return val_->id() == other.val_->id() && val_->peer_node_id() == other.val_->peer_node_id();
}

nlohmann::json Session::to_json() const {
    nlohmann::json j;
    if (!val_.has_value()) return j;
    j["id"] = to_hex(val_->id());
    j["peer_node_id"] = to_hex(val_->peer_node_id());
    j["suite"] = CipherSuite(val_->suite()).to_json();
    j["expiry_ms"] = val_->expiry_ms();
    return j;
}

Result<Session> Session::from_json(const nlohmann::json& j) {
    try {
        auto id_hex = j["id"].get<std::string>();
        auto id_b = from_hex(id_hex);
        SessionId sid;
        std::copy(id_b.begin(), id_b.end(), sid.begin());

        auto peer_hex = j["peer_node_id"].get<std::string>();
        auto peer_b = from_hex(peer_hex);
        NodeId nid;
        std::copy(peer_b.begin(), peer_b.end(), nid.begin());

        auto cs_r = CipherSuite::from_json(j["suite"]);
        if (!cs_r) return err<Session>(cs_r.error());

        uav_pqc::Timestamp expiry = j["expiry_ms"].get<uav_pqc::Timestamp>();

        crypto::AeadKey dummy_send = crypto::AeadKey::from_bytes(std::vector<std::byte>(32, std::byte{0}));
        crypto::AeadKey dummy_recv = crypto::AeadKey::from_bytes(std::vector<std::byte>(32, std::byte{0}));

        session::Session sess(sid, nid, cs_r.value().value(), std::move(dummy_send), std::move(dummy_recv), {}, {}, expiry);
        return ok<Session>(Session(std::move(sess)));
    } catch (...) {
        return err<Session>(ErrorCode::InvalidArgument, "Invalid Session JSON");
    }
}


// ── 19. PacketHeader ─────────────────────────────────────────────────────────
Bytes PacketHeader::serialize() const {
    Bytes b(29);
    b[0] = std::byte{0xD2}; // Magic
    b[1] = std::byte{0x01}; // Version
    b[2] = static_cast<std::byte>(type_);
    std::copy_n(session_id_.data(), 16, b.data() + 3);
    write_u64_be(MutableByteSpan{b.data() + 19, 8}, seq_num_);
    write_u16_be(b.data() + 27, length_);
    return b;
}

Result<PacketHeader> PacketHeader::deserialize(ByteSpan bytes) {
    if (bytes.size() < 29) {
        return err<PacketHeader>(ErrorCode::InvalidArgument, "Truncated PacketHeader bytes");
    }
    if (bytes[0] != std::byte{0xD2} || bytes[1] != std::byte{0x01}) {
        return err<PacketHeader>(ErrorCode::InvalidArgument, "Malformed magic/version in PacketHeader");
    }
    std::uint8_t type = static_cast<std::uint8_t>(bytes[2]);
    SessionId sid;
    std::copy_n(bytes.data() + 3, 16, sid.data());
    std::uint64_t seq = read_u64_be(bytes.subspan(19, 8));
    std::uint16_t len = read_u16_be(bytes.data() + 27);
    return ok<PacketHeader>(PacketHeader(type, sid, seq, len));
}

VoidResult PacketHeader::validate() const {
    return ok();
}

nlohmann::json PacketHeader::to_json() const {
    nlohmann::json j;
    j["type"] = type_;
    j["session_id"] = to_hex(session_id_);
    j["seq_num"] = seq_num_;
    j["length"] = length_;
    return j;
}

Result<PacketHeader> PacketHeader::from_json(const nlohmann::json& j) {
    try {
        std::uint8_t type = j["type"].get<std::uint8_t>();
        auto sid_hex = j["session_id"].get<std::string>();
        auto b = from_hex(sid_hex);
        SessionId sid;
        std::copy(b.begin(), b.end(), sid.begin());
        std::uint64_t seq = j["seq_num"].get<std::uint64_t>();
        std::uint16_t len = j["length"].get<std::uint16_t>();
        return ok<PacketHeader>(PacketHeader(type, sid, seq, len));
    } catch (...) {
        return err<PacketHeader>(ErrorCode::InvalidArgument, "Invalid PacketHeader JSON");
    }
}


// ── 20. Packet ───────────────────────────────────────────────────────────────
Bytes Packet::serialize() const {
    Bytes b = header_.serialize();
    b.insert(b.end(), payload_.begin(), payload_.end());
    return b;
}

Result<Packet> Packet::deserialize(ByteSpan bytes) {
    if (bytes.size() < 29) {
        return err<Packet>(ErrorCode::InvalidArgument, "Truncated Packet bytes");
    }
    auto hdr_r = PacketHeader::deserialize(bytes.subspan(0, 29));
    if (!hdr_r) return err<Packet>(hdr_r.error());
    const auto& hdr = hdr_r.value();
    if (bytes.size() < static_cast<std::size_t>(29 + hdr.length())) {
        return err<Packet>(ErrorCode::InvalidArgument, "Truncated Packet payload bytes");
    }
    Bytes payload(bytes.data() + 29, bytes.data() + 29 + hdr.length());
    return ok<Packet>(Packet(hdr, std::move(payload)));
}

VoidResult Packet::validate() const {
    if (header_.length() != payload_.size()) {
        return err(ErrorCode::PolicyViolation, "Header payload length does not match payload size");
    }
    return ok();
}

nlohmann::json Packet::to_json() const {
    nlohmann::json j;
    j["header"] = header_.to_json();
    j["payload"] = to_hex(payload_);
    return j;
}

Result<Packet> Packet::from_json(const nlohmann::json& j) {
    try {
        auto hdr_r = PacketHeader::from_json(j["header"]);
        if (!hdr_r) return err<Packet>(hdr_r.error());
        auto payload_hex = j["payload"].get<std::string>();
        Bytes payload = from_hex(payload_hex);
        return ok<Packet>(Packet(hdr_r.value(), std::move(payload)));
    } catch (...) {
        return err<Packet>(ErrorCode::InvalidArgument, "Invalid Packet JSON");
    }
}

} // namespace uav_pqc::types
