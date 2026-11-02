// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/protocol/registration.hpp"
#include "uav_pqc/protocol/message.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/identity/trust_chain.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"
#include "uav_pqc/crypto/default_provider.hpp"
#include <nlohmann/json.hpp>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace uav_pqc::protocol {

namespace {

void write_u16_be(std::byte* dest, std::uint16_t val) noexcept {
    dest[0] = static_cast<std::byte>((val >> 8) & 0xFF);
    dest[1] = static_cast<std::byte>(val & 0xFF);
}

std::uint16_t read_u16_be(const std::byte* src) noexcept {
    return (static_cast<std::uint16_t>(src[0]) << 8) | static_cast<std::uint16_t>(src[1]);
}

void write_u32_be(std::byte* dest, std::uint32_t val) noexcept {
    dest[0] = static_cast<std::byte>((val >> 24) & 0xFF);
    dest[1] = static_cast<std::byte>((val >> 16) & 0xFF);
    dest[2] = static_cast<std::byte>((val >> 8) & 0xFF);
    dest[3] = static_cast<std::byte>(val & 0xFF);
}

std::uint32_t read_u32_be(const std::byte* src) noexcept {
    return (static_cast<std::uint32_t>(src[0]) << 24) |
           (static_cast<std::uint32_t>(src[1]) << 16) |
           (static_cast<std::uint32_t>(src[2]) << 8) |
           static_cast<std::uint32_t>(src[3]);
}

void write_u64_be(std::byte* dest, std::uint64_t val) noexcept {
    for (int i = 7; i >= 0; --i) {
        dest[7 - i] = static_cast<std::byte>((val >> (i * 8)) & 0xFF);
    }
}

std::uint64_t read_u64_be(const std::byte* src) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<std::uint8_t>(src[i]);
    }
    return v;
}

void append_len16_bytes(Bytes& dest, ByteSpan src) {
    const std::uint16_t len = static_cast<std::uint16_t>(src.size());
    std::byte len_buf[2];
    write_u16_be(len_buf, len);
    dest.push_back(len_buf[0]);
    dest.push_back(len_buf[1]);
    dest.insert(dest.end(), src.begin(), src.end());
}

Result<Bytes> read_len16_bytes(const std::byte*& ptr, const std::byte* end) {
    if (ptr + 2 > end) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Truncated length prefix");
    }
    const std::uint16_t len = read_u16_be(ptr);
    ptr += 2;
    if (ptr + len > end) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Truncated value body");
    }
    Bytes res(ptr, ptr + len);
    ptr += len;
    return ok<Bytes>(std::move(res));
}

void append_len16_string(Bytes& dest, const std::string& str) {
    append_len16_bytes(dest, ByteSpan{reinterpret_cast<const std::byte*>(str.data()), str.size()});
}

Result<std::string> read_len16_string(const std::byte*& ptr, const std::byte* end) {
    auto res_r = read_len16_bytes(ptr, end);
    if (!res_r) return err<std::string>(res_r.error());
    return ok<std::string>(std::string(reinterpret_cast<const char*>(res_r.value().data()), res_r.value().size()));
}

std::string to_hex_str(ByteSpan bytes) {
    std::stringstream ss;
    for (auto b : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

Bytes from_hex_str(const std::string& hex) {
    Bytes bytes;
    bytes.reserve(hex.length() / 2);
    for (std::size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        std::byte b = static_cast<std::byte>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(b);
    }
    return bytes;
}

crypto::DsaKeyPair clone_keypair(const crypto::DsaKeyPair& kp) {
    crypto::DsaKeyPair copy;
    copy.public_key = kp.public_key;
    Bytes bytes_copy(kp.private_key.data.bytes().begin(), kp.private_key.data.bytes().end());
    copy.private_key.data = SecureBytes(std::move(bytes_copy));
    return copy;
}

} // namespace

// ── RegisterReq ──────────────────────────────────────────────────────────────

Bytes RegisterReq::get_to_be_signed_bytes() const {
    Bytes out;
    out.insert(out.end(), node_id.begin(), node_id.end());
    append_len16_string(out, subject_name);
    append_len16_bytes(out, ecdsa_pub.data);
    append_len16_bytes(out, mldsa_pub.data);
    
    std::byte ts_buf[8];
    write_u64_be(ts_buf, timestamp);
    out.insert(out.end(), ts_buf, ts_buf + 8);
    
    append_len16_bytes(out, nonce);
    return out;
}

Bytes RegisterReq::serialise() const {
    Bytes out = get_to_be_signed_bytes();
    append_len16_bytes(out, signature);
    return out;
}

Result<RegisterReq> RegisterReq::deserialise(ByteSpan data) {
    if (data.size() < 32) {
        return err<RegisterReq>(ErrorCode::InvalidArgument, "Data too short for RegisterReq");
    }
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();
    
    RegisterReq req;
    std::copy(ptr, ptr + 32, req.node_id.begin());
    ptr += 32;
    
    auto name_r = read_len16_string(ptr, end);
    if (!name_r) return err<RegisterReq>(name_r.error());
    req.subject_name = std::move(name_r.value());
    
    auto ecdsa_r = read_len16_bytes(ptr, end);
    if (!ecdsa_r) return err<RegisterReq>(ecdsa_r.error());
    req.ecdsa_pub.data = std::move(ecdsa_r.value());
    
    auto mldsa_r = read_len16_bytes(ptr, end);
    if (!mldsa_r) return err<RegisterReq>(mldsa_r.error());
    req.mldsa_pub.data = std::move(mldsa_r.value());
    
    if (ptr + 8 > end) {
        return err<RegisterReq>(ErrorCode::InvalidArgument, "Truncated timestamp");
    }
    req.timestamp = read_u64_be(ptr);
    ptr += 8;
    
    auto nonce_r = read_len16_bytes(ptr, end);
    if (!nonce_r) return err<RegisterReq>(nonce_r.error());
    req.nonce = std::move(nonce_r.value());
    
    auto sig_r = read_len16_bytes(ptr, end);
    if (!sig_r) return err<RegisterReq>(sig_r.error());
    req.signature = std::move(sig_r.value());
    
    return ok<RegisterReq>(std::move(req));
}

// ── RegisterAck ──────────────────────────────────────────────────────────────

Bytes RegisterAck::get_to_be_signed_bytes() const {
    Bytes out;
    append_len16_bytes(out, ca_cert.raw_der());
    append_len16_bytes(out, uav_cert.raw_der());
    append_len16_bytes(out, nonce);
    return out;
}

Bytes RegisterAck::serialise() const {
    Bytes out = get_to_be_signed_bytes();
    append_len16_bytes(out, signature);
    return out;
}

Result<RegisterAck> RegisterAck::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();
    
    auto ca_der_r = read_len16_bytes(ptr, end);
    if (!ca_der_r) return err<RegisterAck>(ca_der_r.error());
    auto ca_cert_r = identity::Certificate::from_der(std::move(ca_der_r.value()));
    if (!ca_cert_r) return err<RegisterAck>(ca_cert_r.error());
    
    auto uav_der_r = read_len16_bytes(ptr, end);
    if (!uav_der_r) return err<RegisterAck>(uav_der_r.error());
    auto uav_cert_r = identity::Certificate::from_der(std::move(uav_der_r.value()));
    if (!uav_cert_r) return err<RegisterAck>(uav_cert_r.error());
    
    auto nonce_r = read_len16_bytes(ptr, end);
    if (!nonce_r) return err<RegisterAck>(nonce_r.error());
    
    auto sig_r = read_len16_bytes(ptr, end);
    if (!sig_r) return err<RegisterAck>(sig_r.error());
    
    RegisterAck ack;
    ack.ca_cert = std::move(ca_cert_r.value());
    ack.uav_cert = std::move(uav_cert_r.value());
    ack.nonce = std::move(nonce_r.value());
    ack.signature = std::move(sig_r.value());
    
    return ok<RegisterAck>(std::move(ack));
}

// ── RegisterReject ───────────────────────────────────────────────────────────

Bytes RegisterReject::serialise() const {
    Bytes out;
    append_len16_bytes(out, nonce);
    
    std::byte res_buf[4];
    write_u32_be(res_buf, static_cast<std::uint32_t>(reason));
    out.insert(out.end(), res_buf, res_buf + 4);
    
    append_len16_string(out, description);
    return out;
}

Result<RegisterReject> RegisterReject::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();
    
    auto nonce_r = read_len16_bytes(ptr, end);
    if (!nonce_r) return err<RegisterReject>(nonce_r.error());
    
    if (ptr + 4 > end) {
        return err<RegisterReject>(ErrorCode::InvalidArgument, "Truncated reason");
    }
    std::uint32_t reason_val = read_u32_be(ptr);
    ptr += 4;
    
    auto desc_r = read_len16_string(ptr, end);
    if (!desc_r) return err<RegisterReject>(desc_r.error());
    
    RegisterReject rej;
    rej.nonce = std::move(nonce_r.value());
    rej.reason = static_cast<RegisterRejectReason>(reason_val);
    rej.description = std::move(desc_r.value());
    
    return ok<RegisterReject>(std::move(rej));
}

// ── RegistrationDatabase ─────────────────────────────────────────────────────

VoidResult RegistrationDatabase::deserialize_json(const std::string& json_str) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_str);
    } catch (const std::exception& e) {
        return err(ErrorCode::InternalError, std::string("JSON parse failed: ") + e.what());
    }
    records_.clear();
    if (j.contains("records") && j["records"].is_array()) {
        for (const auto& item : j["records"]) {
            Record rec;
            auto hex_node = item["node_id"].get<std::string>();
            auto node_bytes = from_hex_str(hex_node);
            if (node_bytes.size() == 32) {
                std::copy(node_bytes.begin(), node_bytes.end(), rec.node_id.begin());
            }
            rec.subject_name = item["subject_name"].get<std::string>();
            rec.ecdsa_pub.data = from_hex_str(item["ecdsa_pub"].get<std::string>());
            rec.mldsa_pub.data = from_hex_str(item["mldsa_pub"].get<std::string>());
            auto cert_der = from_hex_str(item["uav_cert"].get<std::string>());
            auto cert_r = identity::Certificate::from_der(std::move(cert_der));
            if (cert_r) {
                rec.uav_cert = std::move(cert_r.value());
            }
            rec.registered_at = item["registered_at"].get<Timestamp>();
            records_.push_back(std::move(rec));
        }
    }
    return ok();
}

std::string RegistrationDatabase::serialize_json() const {
    nlohmann::json j;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& rec : records_) {
        nlohmann::json item;
        item["node_id"] = to_hex_str(ByteSpan{rec.node_id.data(), 32});
        item["subject_name"] = rec.subject_name;
        item["ecdsa_pub"] = to_hex_str(rec.ecdsa_pub.data);
        item["mldsa_pub"] = to_hex_str(rec.mldsa_pub.data);
        item["uav_cert"] = to_hex_str(rec.uav_cert.raw_der());
        item["registered_at"] = rec.registered_at;
        arr.push_back(item);
    }
    j["records"] = arr;
    return j.dump(4);
}

bool RegistrationDatabase::is_registered(const NodeId& node_id) const {
    return std::any_of(records_.begin(), records_.end(),
        [&](const Record& r) { return r.node_id == node_id; });
}

bool RegistrationDatabase::is_subject_name_registered(const std::string& subject_name) const {
    return std::any_of(records_.begin(), records_.end(),
        [&](const Record& r) { return r.subject_name == subject_name; });
}

std::optional<RegistrationDatabase::Record> RegistrationDatabase::get_record(const NodeId& node_id) const {
    auto it = std::find_if(records_.begin(), records_.end(),
        [&](const Record& r) { return r.node_id == node_id; });
    if (it != records_.end()) {
        return *it;
    }
    return std::nullopt;
}

VoidResult RegistrationDatabase::add_record(Record record) {
    records_.push_back(std::move(record));
    return ok();
}

std::vector<RegistrationDatabase::Record> RegistrationDatabase::get_all_records() const {
    return records_;
}

bool RegistrationDatabase::check_and_track_nonce(const Bytes& nonce) {
    if (seen_nonces_.find(nonce) != seen_nonces_.end()) {
        return false;
    }
    seen_nonces_.insert(nonce);
    return true;
}

void RegistrationDatabase::prune_seen_nonces(Timestamp max_age_ms) {
    (void)max_age_ms;
    if (seen_nonces_.size() > 1000) {
        seen_nonces_.clear();
    }
}

void RegistrationDatabase::clear() {
    records_.clear();
    seen_nonces_.clear();
}

// ── UavRegistrar ─────────────────────────────────────────────────────────────

UavRegistrar::UavRegistrar(std::shared_ptr<platform::IClock> clock,
                           std::shared_ptr<crypto::ICryptoProvider> provider)
    : clock_(clock), crypto_provider_(std::move(provider)) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    if (!crypto_provider_) {
        crypto_provider_ = std::make_shared<crypto::DefaultCryptoProvider>();
    }
}

Result<Bytes> UavRegistrar::initiate_registration(
    const std::string& subject_name,
    const crypto::DsaKeyPair& ecdsa_kp,
    const crypto::DsaKeyPair& mldsa_kp,
    Timestamp now_ms) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Registration);
    
    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    subject_name_ = subject_name;
    ecdsa_kp_ = clone_keypair(ecdsa_kp);
    mldsa_kp_ = clone_keypair(mldsa_kp);
    state_ = State::Registering;

    RegisterReq req;
    std::copy(mldsa_kp_.public_key.data.begin(), mldsa_kp_.public_key.data.begin() + 32, req.node_id.begin());
    req.subject_name = subject_name_;
    req.ecdsa_pub = ecdsa_kp_.public_key;
    req.mldsa_pub = mldsa_kp_.public_key;
    req.timestamp = current_time;

    // Generate nonce
    auto rand_bytes_r = crypto_provider_->generate_random_bytes(16);
    if (!rand_bytes_r) {
        state_ = State::Failed;
        return err<Bytes>(rand_bytes_r.error());
    }
    req.nonce = std::move(rand_bytes_r.value());
    sent_nonce_ = req.nonce;

    auto mldsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
    auto sig_r = mldsa->sign(mldsa_kp_.private_key, req.get_to_be_signed_bytes());
    if (!sig_r) {
        state_ = State::Failed;
        return err<Bytes>(sig_r.error());
    }
    req.signature = std::move(sig_r.value().data);

    Bytes body = req.serialise();
    MessageHeader hdr;
    hdr.type = MessageType::RegisterReq;
    hdr.length = static_cast<std::uint16_t>(body.size());
    
    Bytes pkt = hdr.serialise();
    pkt.insert(pkt.end(), body.begin(), body.end());
    
    UAV_PQC_LOG_INFO("protocol.registration", "UAV initiated registration for subject='{}'", subject_name_);
    return ok<Bytes>(std::move(pkt));
}

VoidResult UavRegistrar::handle_registration_response(
    ByteSpan response_msg,
    const identity::Certificate& ca_anchor,
    Timestamp now_ms) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Registration);
    
    Timestamp cert_time = now_ms;
    if (cert_time == 0 && clock_) {
        cert_time = clock_->wall_clock_ms();
    }

    if (response_msg.size() < MessageHeader::kWireSize) {
        state_ = State::Failed;
        return err(ErrorCode::InvalidArgument, "Response too short");
    }

    auto hdr_r = MessageHeader::deserialise(response_msg.subspan(0, MessageHeader::kWireSize));
    if (!hdr_r) {
        state_ = State::Failed;
        return err(hdr_r.error());
    }

    ByteSpan body = response_msg.subspan(MessageHeader::kWireSize, hdr_r.value().length);

    if (hdr_r.value().type == MessageType::RegisterAck) {
        auto ack_r = RegisterAck::deserialise(body);
        if (!ack_r) {
            state_ = State::Failed;
            return err(ack_r.error());
        }

        const auto& ack = ack_r.value();

        if (ack.nonce != sent_nonce_) {
            state_ = State::Failed;
            return err(ErrorCode::AuthenticationFailed, "Echoed nonce mismatch");
        }

        auto mldsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
        crypto::Signature sig;
        sig.data = ack.signature;
        
        auto verify_r = mldsa->verify(ca_anchor.ml_dsa_public_key(), ack.get_to_be_signed_bytes(), sig);
        if (!verify_r.has_value() || !verify_r.value()) {
            state_ = State::Failed;
            return err(ErrorCode::VerificationFailed, "CA signature on RegisterAck failed");
        }

        identity::TrustChain trust_chain({ ca_anchor }, clock_);
        auto val_r = trust_chain.validate({ ack.uav_cert, ca_anchor }, cert_time);
        if (!val_r) {
            state_ = State::Failed;
            return err(val_r.error());
        }

        uav_cert_ = ack.uav_cert;
        ca_cert_ = ack.ca_cert;
        state_ = State::Registered;
        UAV_PQC_LOG_INFO("protocol.registration", "UAV registration completed successfully");
        return ok();
    } 
    else if (hdr_r.value().type == MessageType::RegisterReject) {
        auto rej_r = RegisterReject::deserialise(body);
        state_ = State::Failed;
        if (!rej_r) {
            return err(ErrorCode::AuthenticationFailed, "Registration rejected");
        }
        UAV_PQC_LOG_WARN("protocol.registration", "Registration rejected: {} (reason={})", 
                         rej_r.value().description, static_cast<std::uint32_t>(rej_r.value().reason));
        return err(ErrorCode::AuthenticationFailed, "Registration rejected: " + rej_r.value().description);
    }

    state_ = State::Failed;
    return err(ErrorCode::UnsupportedOperation, "Unexpected registration response type");
}

// ── GcsRegistrar ─────────────────────────────────────────────────────────────

GcsRegistrar::GcsRegistrar(RegistrationDatabase& db, app::ICertificateAuthority& ca,
                           std::shared_ptr<platform::IClock> clock,
                           std::shared_ptr<crypto::ICryptoProvider> provider)
    : db_(db), ca_(ca), clock_(clock), crypto_provider_(std::move(provider)) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    if (!crypto_provider_) {
        crypto_provider_ = std::make_shared<crypto::DefaultCryptoProvider>();
    }
}

Result<Bytes> GcsRegistrar::process_registration_request(ByteSpan request_msg, Timestamp now_ms) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Registration);
    if (request_msg.size() < MessageHeader::kWireSize) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Request message too short");
    }

    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    Timestamp cert_time = now_ms;
    if (cert_time == 0 && clock_) {
        cert_time = clock_->wall_clock_ms();
    }

    auto hdr_r = MessageHeader::deserialise(request_msg.subspan(0, MessageHeader::kWireSize));
    if (!hdr_r) return err<Bytes>(hdr_r.error());

    if (hdr_r.value().type != MessageType::RegisterReq) {
        return err<Bytes>(ErrorCode::UnsupportedOperation, "Expected RegisterReq message");
    }

    ByteSpan body = request_msg.subspan(MessageHeader::kWireSize, hdr_r.value().length);
    auto req_r = RegisterReq::deserialise(body);
    if (!req_r) return err<Bytes>(req_r.error());

    const auto& req = req_r.value();

    auto reject_response = [&](RegisterRejectReason reason, const std::string& desc) -> Result<Bytes> {
        RegisterReject rej;
        rej.nonce = req.nonce;
        rej.reason = reason;
        rej.description = desc;
        Bytes rej_body = rej.serialise();
        
        MessageHeader rej_hdr;
        rej_hdr.type = MessageType::RegisterReject;
        rej_hdr.length = static_cast<std::uint16_t>(rej_body.size());
        
        Bytes pkt = rej_hdr.serialise();
        pkt.insert(pkt.end(), rej_body.begin(), rej_body.end());
        return ok<Bytes>(std::move(pkt));
    };

    // 1. Check timestamp (±5 mins tolerance)
    std::int64_t diff = static_cast<std::int64_t>(req.timestamp) - static_cast<std::int64_t>(current_time);
    if (std::abs(diff) > 300000) {
        return reject_response(RegisterRejectReason::ExpiredTimestamp, "Timestamp expired or out of sync");
    }

    // 2. Check nonce replay
    if (!db_.check_and_track_nonce(req.nonce)) {
        return reject_response(RegisterRejectReason::ReplayDetected, "Replayed nonce detected");
    }

    // 3. Verify ML-DSA signature
    auto mldsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
    crypto::Signature sig;
    sig.data = req.signature;
    auto verify_r = mldsa->verify(req.mldsa_pub, req.get_to_be_signed_bytes(), sig);
    if (!verify_r.has_value() || !verify_r.value()) {
        return reject_response(RegisterRejectReason::InvalidSignature, "UAV signature verification failed");
    }

    // 4. Verify duplicate NodeId/subject name
    if (db_.is_registered(req.node_id)) {
        return reject_response(RegisterRejectReason::DuplicateNodeId, "Node ID already registered");
    }
    if (db_.is_subject_name_registered(req.subject_name)) {
        return reject_response(RegisterRejectReason::DuplicateSubjectName, "Subject name already registered");
    }

    // 5. Issue certificate
    auto cert_r = ca_.issue_certificate(req.subject_name, req.node_id, req.ecdsa_pub, req.mldsa_pub, 31536000000ULL, cert_time);
    if (!cert_r) {
        return reject_response(RegisterRejectReason::CaFailure, "CA certificate issuance failed: " + cert_r.error().message);
    }

    // 6. Add record to DB
    RegistrationDatabase::Record record;
    record.node_id = req.node_id;
    record.subject_name = req.subject_name;
    record.ecdsa_pub = req.ecdsa_pub;
    record.mldsa_pub = req.mldsa_pub;
    record.uav_cert = cert_r.value();
    record.registered_at = cert_time;
    
    if (!db_.add_record(std::move(record))) {
        return reject_response(RegisterRejectReason::CaFailure, "Failed to save record to DB");
    }

    // 7. Construct and sign REGISTER_ACK
    RegisterAck ack;
    if (ca_.get_ca_certificate()) {
        ack.ca_cert = *ca_.get_ca_certificate();
    }
    ack.uav_cert = cert_r.value();
    ack.nonce = req.nonce;

    auto ca_sig_r = ca_.sign_data(ack.get_to_be_signed_bytes());
    if (!ca_sig_r) {
        return reject_response(RegisterRejectReason::CaFailure, "Failed to sign RegisterAck");
    }
    ack.signature = std::move(ca_sig_r.value());

    Bytes ack_body = ack.serialise();
    MessageHeader ack_hdr;
    ack_hdr.type = MessageType::RegisterAck;
    ack_hdr.length = static_cast<std::uint16_t>(ack_body.size());

    Bytes pkt = ack_hdr.serialise();
    pkt.insert(pkt.end(), ack_body.begin(), ack_body.end());
    UAV_PQC_LOG_INFO("protocol.registration", "GCS processed registration request successfully for subject='{}'", req.subject_name);
    return ok<Bytes>(std::move(pkt));
}

} // namespace uav_pqc::protocol
