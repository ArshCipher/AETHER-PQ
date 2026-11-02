// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include <nlohmann/json.hpp>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace uav_pqc::app {

namespace {

std::string to_hex_string(ByteSpan bytes) {
    std::stringstream ss;
    for (auto b : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

Bytes from_hex_string(const std::string& hex) {
    Bytes bytes;
    bytes.reserve(hex.length() / 2);
    for (std::size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        std::byte b = static_cast<std::byte>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(b);
    }
    return bytes;
}

std::uint64_t read_u64(ByteSpan sp) noexcept {
    if (sp.size() < 8) return 0;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<std::uint8_t>(sp[i]);
    }
    return v;
}

struct TlvCursor {
    const std::byte* ptr;
    const std::byte* end;

    bool has_bytes(std::size_t n) const noexcept {
        return static_cast<std::size_t>(end - ptr) >= n;
    }

    std::uint8_t read_u8() {
        return static_cast<std::uint8_t>(*ptr++);
    }

    std::size_t read_length() {
        const auto b = read_u8();
        if (b <= 0x7F) return b;
        if (b == 0x82) {
            if (!has_bytes(2)) return 0;
            const std::size_t hi = static_cast<std::uint8_t>(*ptr++);
            const std::size_t lo = static_cast<std::uint8_t>(*ptr++);
            return (hi << 8) | lo;
        }
        return 0;
    }

    ByteSpan read_value(std::size_t len) {
        if (!has_bytes(len)) return {};
        ByteSpan sp{ptr, len};
        ptr += len;
        return sp;
    }

    Bytes read_tlv_value(std::uint8_t expected_tag) {
        if (!has_bytes(2)) return {};
        const auto tag = read_u8();
        if (tag != expected_tag) { --ptr; return {}; }
        const std::size_t len = read_length();
        const auto span = read_value(len);
        return Bytes(span.begin(), span.end());
    }
};

} // namespace

CertificateAuthority::CertificateAuthority(NodeId ca_node_id, crypto::DsaKeyPair ca_keypair)
    : ca_node_id_(ca_node_id), ca_keypair_(std::move(ca_keypair)) {}

Result<identity::Certificate> CertificateAuthority::issue_certificate(
    const std::string& subject_name,
    const NodeId& subject_id,
    const crypto::DsaPublicKey& ecdsa_pub,
    const crypto::DsaPublicKey& mldsa_pub,
    Timestamp lifetime_ms,
    Timestamp now_ms) {
    
    std::lock_guard<std::mutex> lock(mutex_);

    // 1. Construct tbsCertificate
    Bytes tbs;
    tbs.push_back(std::byte{0x30}); // SEQUENCE
    tbs.push_back(std::byte{0x82}); // inner length placeholder
    tbs.push_back(std::byte{0x00});
    tbs.push_back(std::byte{0x00});

    // subject_name (tag 0x0C)
    tbs.push_back(std::byte{0x0C});
    tbs.push_back(static_cast<std::byte>(subject_name.size()));
    for (char c : subject_name) {
        tbs.push_back(static_cast<std::byte>(c));
    }

    // subject_node_id (tag 0x04, 16 bytes)
    tbs.push_back(std::byte{0x04});
    tbs.push_back(std::byte{16});
    tbs.insert(tbs.end(), subject_id.begin(), subject_id.begin() + 16);

    // issuer_node_id (tag 0x04, 16 bytes)
    tbs.push_back(std::byte{0x04});
    tbs.push_back(std::byte{16});
    tbs.insert(tbs.end(), ca_node_id_.begin(), ca_node_id_.begin() + 16);

    // not_before_ms (tag 0x02, 8 bytes)
    tbs.push_back(std::byte{0x02});
    tbs.push_back(std::byte{8});
    for (int i = 7; i >= 0; --i) {
        tbs.push_back(static_cast<std::byte>((now_ms >> (i * 8)) & 0xFF));
    }

    // not_after_ms (tag 0x02, 8 bytes)
    Timestamp not_after = now_ms + lifetime_ms;
    tbs.push_back(std::byte{0x02});
    tbs.push_back(std::byte{8});
    for (int i = 7; i >= 0; --i) {
        tbs.push_back(static_cast<std::byte>((not_after >> (i * 8)) & 0xFF));
    }

    // key_type (tag 0x02, 1 byte)
    tbs.push_back(std::byte{0x02});
    tbs.push_back(std::byte{1});
    
    // Choose appropriate flag depending on available keys
    std::uint8_t flags = 0;
    if (!ecdsa_pub.data.empty()) flags |= 0x01;
    if (!mldsa_pub.data.empty()) flags |= 0x04;
    tbs.push_back(static_cast<std::byte>(flags));

    // ECDSA pub key (tag 0x04, 65 bytes)
    if (!ecdsa_pub.data.empty()) {
        tbs.push_back(std::byte{0x04});
        tbs.push_back(static_cast<std::byte>(ecdsa_pub.data.size()));
        tbs.insert(tbs.end(), ecdsa_pub.data.begin(), ecdsa_pub.data.end());
    }

    // ML-DSA pub key (tag 0x04)
    if (!mldsa_pub.data.empty()) {
        tbs.push_back(std::byte{0x04});
        std::uint16_t mldsa_len = static_cast<std::uint16_t>(mldsa_pub.data.size());
        if (mldsa_len <= 127) {
            tbs.push_back(static_cast<std::byte>(mldsa_len));
        } else {
            tbs.push_back(std::byte{0x82});
            tbs.push_back(static_cast<std::byte>((mldsa_len >> 8) & 0xFF));
            tbs.push_back(static_cast<std::byte>(mldsa_len & 0xFF));
        }
        tbs.insert(tbs.end(), mldsa_pub.data.begin(), mldsa_pub.data.end());
    }

    // Adjust inner sequence length
    std::uint16_t inner_len = static_cast<std::uint16_t>(tbs.size() - 4);
    tbs[2] = static_cast<std::byte>((inner_len >> 8) & 0xFF);
    tbs[3] = static_cast<std::byte>(inner_len & 0xFF);

    // 2. Sign To-Be-Signed (tbs) bytes with CA private key
    Bytes sig_bytes;
    if (!ca_keypair_.private_key.data.empty()) {
        crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
        auto sig_r = mldsa.sign(ca_keypair_.private_key, ByteSpan{tbs.data(), tbs.size()});
        if (!sig_r) {
            return err<identity::Certificate>(sig_r.error());
        }
        sig_bytes = std::move(sig_r.value().data);
    }

    // 3. Assemble outer SEQUENCE { tbsCertificate, signatureValue }
    Bytes cert;
    cert.push_back(std::byte{0x30}); // SEQUENCE
    cert.push_back(std::byte{0x82}); // outer length placeholder
    cert.push_back(std::byte{0x00});
    cert.push_back(std::byte{0x00});

    // Insert tbs bytes
    cert.insert(cert.end(), tbs.begin(), tbs.end());

    // Insert signature bytes (tag 0x04)
    if (!sig_bytes.empty()) {
        cert.push_back(std::byte{0x04});
        std::uint16_t sig_len = static_cast<std::uint16_t>(sig_bytes.size());
        if (sig_len <= 127) {
            cert.push_back(static_cast<std::byte>(sig_len));
        } else {
            cert.push_back(std::byte{0x82});
            cert.push_back(static_cast<std::byte>((sig_len >> 8) & 0xFF));
            cert.push_back(static_cast<std::byte>(sig_len & 0xFF));
        }
        cert.insert(cert.end(), sig_bytes.begin(), sig_bytes.end());
    }

    // Adjust outer SEQUENCE length
    std::uint16_t total_len = static_cast<std::uint16_t>(cert.size() - 4);
    cert[2] = static_cast<std::byte>((total_len >> 8) & 0xFF);
    cert[3] = static_cast<std::byte>(total_len & 0xFF);

    auto parsed_cert_r = identity::Certificate::from_der(std::move(cert));
    if (parsed_cert_r) {
        issued_db_.push_back(parsed_cert_r.value());
    }
    return parsed_cert_r;
}

Result<identity::Certificate> CertificateAuthority::generate_root_certificate(
    const std::string& subject_name,
    Timestamp lifetime_ms,
    Timestamp now_ms) {
    
    // Generate new ML-DSA-65 root keypair
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto kp_r = mldsa.generate_keypair();
    if (!kp_r) return err<identity::Certificate>(kp_r.error());

    {
        std::lock_guard<std::mutex> lock(mutex_);
        ca_keypair_ = std::move(kp_r.value());
        // Derive CA NodeID from public key prefix
        std::copy(ca_keypair_.public_key.data.begin(), ca_keypair_.public_key.data.begin() + 16, ca_node_id_.begin());
    }

    auto cert_r = issue_certificate(subject_name, ca_node_id_, crypto::DsaPublicKey{}, ca_keypair_.public_key, lifetime_ms, now_ms);
    if (cert_r) {
        std::lock_guard<std::mutex> lock(mutex_);
        ca_cert_ = cert_r.value();
    }
    return cert_r;
}

Result<identity::Certificate> CertificateAuthority::renew_certificate(
    const identity::Certificate& old_cert,
    Timestamp new_lifetime_ms,
    Timestamp now_ms) {
    
    // Check revocation first
    if (std::any_of(revocation_db_.begin(), revocation_db_.end(),
        [&](const RevocationEntry& e) { return e.node_id == old_cert.subject_node_id(); })) {
        return err<identity::Certificate>(ErrorCode::CertificateRevoked, "Cannot renew a revoked certificate");
    }

    return issue_certificate(
        old_cert.subject_name(),
        old_cert.subject_node_id(),
        old_cert.ecdsa_public_key(),
        old_cert.ml_dsa_public_key(),
        new_lifetime_ms,
        now_ms
    );
}

VoidResult CertificateAuthority::revoke_certificate(
    const NodeId& node_id,
    Timestamp revocation_time,
    std::uint8_t reason) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(revocation_db_.begin(), revocation_db_.end(),
        [&](const RevocationEntry& e) { return e.node_id == node_id; });
    if (it == revocation_db_.end()) {
        revocation_db_.push_back({node_id, revocation_time, reason});
    }
    return ok();
}

Result<Bytes> CertificateAuthority::generate_crl(Timestamp now_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Bytes revoked_list;
    for (const auto& entry : revocation_db_) {
        Bytes item;
        item.push_back(std::byte{0x30}); // SEQUENCE
        item.push_back(std::byte{29}); // len = 16 (node_id) + 10 (time) + 3 (reason)
        
        // node_id
        item.push_back(std::byte{0x04});
        item.push_back(std::byte{16});
        item.insert(item.end(), entry.node_id.begin(), entry.node_id.end());
        
        // revocation_time
        item.push_back(std::byte{0x02});
        item.push_back(std::byte{8});
        for (int i = 7; i >= 0; --i) {
            item.push_back(static_cast<std::byte>((entry.revocation_time >> (i * 8)) & 0xFF));
        }
        
        // reason
        item.push_back(std::byte{0x02});
        item.push_back(std::byte{1});
        item.push_back(static_cast<std::byte>(entry.reason));
        
        revoked_list.insert(revoked_list.end(), item.begin(), item.end());
    }
    
    Bytes crl;
    crl.push_back(std::byte{0x30}); // SEQUENCE
    crl.push_back(std::byte{0x82}); // outer length placeholder
    crl.push_back(std::byte{0x00});
    crl.push_back(std::byte{0x00});
    
    // issuer_node_id
    crl.push_back(std::byte{0x04});
    crl.push_back(std::byte{16});
    crl.insert(crl.end(), ca_node_id_.begin(), ca_node_id_.end());
    
    // this_update
    crl.push_back(std::byte{0x02});
    crl.push_back(std::byte{8});
    for (int i = 7; i >= 0; --i) {
        crl.push_back(static_cast<std::byte>((now_ms >> (i * 8)) & 0xFF));
    }
    
    // revoked_certs SEQUENCE
    crl.push_back(std::byte{0x30});
    std::uint16_t list_len = static_cast<std::uint16_t>(revoked_list.size());
    if (list_len <= 127) {
        crl.push_back(static_cast<std::byte>(list_len));
    } else {
        crl.push_back(std::byte{0x82});
        crl.push_back(static_cast<std::byte>((list_len >> 8) & 0xFF));
        crl.push_back(static_cast<std::byte>(list_len & 0xFF));
    }
    crl.insert(crl.end(), revoked_list.begin(), revoked_list.end());
    
    // Adjust total CRL SEQUENCE length
    std::uint16_t total_len = static_cast<std::uint16_t>(crl.size() - 4);
    crl[2] = static_cast<std::byte>((total_len >> 8) & 0xFF);
    crl[3] = static_cast<std::byte>(total_len & 0xFF);
    
    return ok<Bytes>(std::move(crl));
}

VoidResult CertificateAuthority::import_crl(ByteSpan crl_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (crl_bytes.size() < 4) {
        return err(ErrorCode::InvalidArgument, "CRL too short");
    }
    TlvCursor cursor{crl_bytes.data(), crl_bytes.data() + crl_bytes.size()};
    if (cursor.read_u8() != 0x30) {
        return err(ErrorCode::InvalidArgument, "Invalid CRL tag");
    }
    cursor.read_length(); // skip outer len
    
    // Read issuer_node_id
    auto issuer = cursor.read_tlv_value(0x04);
    if (issuer.size() != 16) {
        return err(ErrorCode::InvalidArgument, "Invalid CRL issuer node ID");
    }
    
    // Read this_update
    cursor.read_tlv_value(0x02);
    
    // Read revoked_certs SEQUENCE
    if (cursor.ptr >= cursor.end || cursor.read_u8() != 0x30) {
        return err(ErrorCode::InvalidArgument, "Invalid CRL revoked_certs sequence tag");
    }
    std::size_t list_len = cursor.read_length();
    TlvCursor list_cursor{cursor.ptr, cursor.ptr + list_len};
    
    while (list_cursor.ptr < list_cursor.end) {
        if (list_cursor.read_u8() != 0x30) break;
        list_cursor.read_length();
        
        auto sub_bytes = list_cursor.read_tlv_value(0x04);
        if (sub_bytes.size() != 16) break;
        
        auto time_bytes = list_cursor.read_tlv_value(0x02);
        Timestamp time = read_u64(ByteSpan{time_bytes.data(), time_bytes.size()});
        
        auto reason_bytes = list_cursor.read_tlv_value(0x02);
        std::uint8_t reason = 0;
        if (!reason_bytes.empty()) {
            reason = static_cast<std::uint8_t>(reason_bytes[0]);
        }
        
        NodeId node_id;
        std::copy(sub_bytes.begin(), sub_bytes.end(), node_id.begin());
        
        auto it = std::find_if(revocation_db_.begin(), revocation_db_.end(),
            [&](const RevocationEntry& e) { return e.node_id == node_id; });
        if (it == revocation_db_.end()) {
            revocation_db_.push_back({node_id, time, reason});
        }
    }
    return ok();
}

std::vector<identity::Certificate> CertificateAuthority::get_issued_certificates() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return issued_db_;
}

std::vector<NodeId> CertificateAuthority::get_revoked_node_ids() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NodeId> ids;
    ids.reserve(revocation_db_.size());
    for (const auto& entry : revocation_db_) {
        ids.push_back(entry.node_id);
    }
    return ids;
}

VoidResult CertificateAuthority::save_to_file(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    nlohmann::json j;
    j["ca_node_id"] = to_hex_string(ByteSpan{ca_node_id_.data(), 16});
    j["ca_private_key"] = to_hex_string(ca_keypair_.private_key.data.span());
    j["ca_public_key"] = to_hex_string(ca_keypair_.public_key.data);
    
    if (ca_cert_) {
        j["ca_cert"] = to_hex_string(ca_cert_->raw_der());
    } else {
        j["ca_cert"] = "";
    }
    
    nlohmann::json issued_arr = nlohmann::json::array();
    for (const auto& cert : issued_db_) {
        issued_arr.push_back(to_hex_string(cert.raw_der()));
    }
    j["issued_db"] = issued_arr;
    
    nlohmann::json revoked_arr = nlohmann::json::array();
    for (const auto& entry : revocation_db_) {
        nlohmann::json entry_json;
        entry_json["node_id"] = to_hex_string(ByteSpan{entry.node_id.data(), 16});
        entry_json["revocation_time"] = entry.revocation_time;
        entry_json["reason"] = entry.reason;
        revoked_arr.push_back(entry_json);
    }
    j["revocation_db"] = revoked_arr;
    
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return err(ErrorCode::InternalError, "Failed to open database file for writing: " + filepath);
    }
    file << j.dump(4);
    return ok();
}

VoidResult CertificateAuthority::load_from_file(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return err(ErrorCode::InternalError, "Failed to open database file for reading: " + filepath);
    }
    
    nlohmann::json j;
    try {
        file >> j;
    } catch (const std::exception& e) {
        return err(ErrorCode::InternalError, std::string("Failed to parse JSON database: ") + e.what());
    }
    
    if (j.contains("ca_node_id") && !j["ca_node_id"].get<std::string>().empty()) {
        auto hex = j["ca_node_id"].get<std::string>();
        auto bytes = from_hex_string(hex);
        if (bytes.size() == 16) {
            std::copy(bytes.begin(), bytes.end(), ca_node_id_.begin());
        }
    }
    
    if (j.contains("ca_private_key") && !j["ca_private_key"].get<std::string>().empty()) {
        auto hex = j["ca_private_key"].get<std::string>();
        ca_keypair_.private_key.data = SecureBytes(from_hex_string(hex));
    }
    
    if (j.contains("ca_public_key") && !j["ca_public_key"].get<std::string>().empty()) {
        auto hex = j["ca_public_key"].get<std::string>();
        ca_keypair_.public_key.data = from_hex_string(hex);
    }
    
    if (j.contains("ca_cert") && !j["ca_cert"].get<std::string>().empty()) {
        auto hex = j["ca_cert"].get<std::string>();
        auto cert_r = identity::Certificate::from_der(from_hex_string(hex));
        if (cert_r) {
            ca_cert_ = std::move(cert_r.value());
        }
    } else {
        ca_cert_ = std::nullopt;
    }
    
    issued_db_.clear();
    if (j.contains("issued_db") && j["issued_db"].is_array()) {
        for (const auto& item : j["issued_db"]) {
            auto hex = item.get<std::string>();
            auto cert_r = identity::Certificate::from_der(from_hex_string(hex));
            if (cert_r) {
                issued_db_.push_back(std::move(cert_r.value()));
            }
        }
    }
    
    revocation_db_.clear();
    if (j.contains("revocation_db") && j["revocation_db"].is_array()) {
        for (const auto& item : j["revocation_db"]) {
            RevocationEntry entry;
            auto hex_node = item["node_id"].get<std::string>();
            auto node_bytes = from_hex_string(hex_node);
            if (node_bytes.size() == 16) {
                std::copy(node_bytes.begin(), node_bytes.end(), entry.node_id.begin());
            }
            entry.revocation_time = item["revocation_time"].get<Timestamp>();
            entry.reason = item["reason"].get<std::uint8_t>();
            revocation_db_.push_back(entry);
        }
    }
    
    return ok();
}

Result<Bytes> CertificateAuthority::sign_data(ByteSpan data) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (ca_keypair_.private_key.data.empty()) {
        return err<Bytes>(ErrorCode::SigningFailed, "CA private key not loaded");
    }
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto sig_r = mldsa.sign(ca_keypair_.private_key, data);
    if (!sig_r) {
        return err<Bytes>(sig_r.error());
    }
    return ok<Bytes>(std::move(sig_r.value().data));
}

} // namespace uav_pqc::app
