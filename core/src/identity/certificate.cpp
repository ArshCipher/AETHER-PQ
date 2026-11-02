// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file certificate.cpp
 * @brief UAV-PQC certificate DER parsing.
 *
 * The minimal TLV wire format (big-endian):
 *
 *   SEQUENCE {
 *     UTF8String  subject_name          (tag 0x0C)
 *     OCTET_STRING subject_node_id      (tag 0x04, 16 bytes)
 *     OCTET_STRING issuer_node_id       (tag 0x04, 16 bytes)
 *     INTEGER     not_before_ms         (tag 0x02, 8 bytes big-endian)
 *     INTEGER     not_after_ms          (tag 0x02, 8 bytes big-endian)
 *     INTEGER     key_type              (tag 0x02, 1 byte)
 *     OCTET_STRING ecdsa_public_key     (tag 0x04, 65 bytes, optional)
 *     OCTET_STRING ml_dsa_public_key    (tag 0x04, varies, optional)
 *   }
 *
 * This is NOT full X.509 — it is a compact, application-specific encoding
 * designed for embedded parsers.  The raw DER is retained for signature
 * verification by the TrustChain.
 *
 * Tag/Length/Value parsing convention:
 *   tag:    1 byte
 *   length: 1 byte (≤ 127) or 0x82 || 2-byte big-endian (≤ 65535)
 *   value:  length bytes
 */

#include "uav_pqc/identity/certificate.hpp"
#include "uav_pqc/common/logging.hpp"
#include <cstring>
#include <iostream>
#include <iomanip>

namespace uav_pqc::identity {

namespace {

// ── Minimal TLV reader ────────────────────────────────────────────────────────

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
        if (b == 0x82) { // 2-byte length follows
            if (!has_bytes(2)) return 0;
            const std::size_t hi = static_cast<std::uint8_t>(*ptr++);
            const std::size_t lo = static_cast<std::uint8_t>(*ptr++);
            return (hi << 8) | lo;
        }
        return 0; // unsupported
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

std::uint64_t read_u64(ByteSpan sp) noexcept {
    if (sp.size() < 8) return 0;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<std::uint8_t>(sp[i]);
    }
    return v;
}

} // anonymous namespace

// ── Certificate::from_der ─────────────────────────────────────────────────────

Result<Certificate> Certificate::from_der(Bytes der_bytes) {
    if (der_bytes.size() < 4) {
        return err<Certificate>(ErrorCode::CertificateInvalid,
            "Certificate DER too short");
    }

    TlvCursor outer_cursor{der_bytes.data(), der_bytes.data() + der_bytes.size()};

    // Outer SEQUENCE (tag 0x30)
    const auto outer_tag = outer_cursor.read_u8();
    if (outer_tag != 0x30) {
        return err<Certificate>(ErrorCode::CertificateInvalid,
            "Certificate DER: expected SEQUENCE tag 0x30");
    }
    const std::size_t outer_len = outer_cursor.read_length();

    Certificate cert;
    cert.raw_der_ = der_bytes;

    // Check if first sub-element tag is 0x30 SEQUENCE (signed envelope format)
    if (outer_cursor.ptr < outer_cursor.end && *outer_cursor.ptr == std::byte{0x30}) {
        const auto tbs_tag = outer_cursor.read_u8();
        const std::size_t tbs_len = outer_cursor.read_length();
        const std::byte* tbs_start = outer_cursor.ptr;

        TlvCursor cursor{outer_cursor.ptr, outer_cursor.ptr + tbs_len};
        outer_cursor.ptr += tbs_len; // advance past TBS

        // Parse TBS fields
        auto name_bytes = cursor.read_tlv_value(0x0C);
        cert.subject_name_ = std::string(reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size());

        auto sub_bytes = cursor.read_tlv_value(0x04);
        if (sub_bytes.size() != 16) {
            return err<Certificate>(ErrorCode::CertificateInvalid, "subject_node_id must be 16 bytes");
        }
        std::copy(sub_bytes.begin(), sub_bytes.end(), cert.subject_.begin());

        auto iss_bytes = cursor.read_tlv_value(0x04);
        if (iss_bytes.size() != 16) {
            return err<Certificate>(ErrorCode::CertificateInvalid, "issuer_node_id must be 16 bytes");
        }
        std::copy(iss_bytes.begin(), iss_bytes.end(), cert.issuer_.begin());

        auto ts1 = cursor.read_tlv_value(0x02);
        cert.not_before_ms_ = read_u64(ByteSpan{ts1.data(), ts1.size()});

        auto ts2 = cursor.read_tlv_value(0x02);
        cert.not_after_ms_ = read_u64(ByteSpan{ts2.data(), ts2.size()});

        auto kt_bytes = cursor.read_tlv_value(0x02);
        if (!kt_bytes.empty()) {
            cert.key_type_ = static_cast<CertKeyType>(static_cast<std::uint8_t>(kt_bytes[0]));
        }

        if (has_key_type(cert.key_type_, CertKeyType::EcdsaP256)) {
            auto pk = cursor.read_tlv_value(0x04);
            if (pk.size() != 65) {
                return err<Certificate>(ErrorCode::CertificateInvalid, "ECDSA-P256 public key must be 65 bytes");
            }
            cert.ecdsa_pk_.data = std::move(pk);
        }

        if (has_key_type(cert.key_type_, CertKeyType::MlDsa65) ||
            has_key_type(cert.key_type_, CertKeyType::MlDsa44) ||
            has_key_type(cert.key_type_, CertKeyType::MlDsa87)) {
            auto pk = cursor.read_tlv_value(0x04);
            if (pk.empty()) {
                return err<Certificate>(ErrorCode::CertificateInvalid, "ML-DSA public key missing");
            }
            cert.ml_dsa_pk_.data = std::move(pk);
        }

        // Reconstruct TBS header + body in tbs_der_ for signature verification
        Bytes tbs_header;
        tbs_header.push_back(std::byte{0x30});
        if (tbs_len <= 127) {
            tbs_header.push_back(static_cast<std::byte>(tbs_len));
        } else {
            tbs_header.push_back(std::byte{0x82});
            tbs_header.push_back(static_cast<std::byte>((tbs_len >> 8) & 0xFF));
            tbs_header.push_back(static_cast<std::byte>(tbs_len & 0xFF));
        }
        cert.tbs_der_ = tbs_header;
        cert.tbs_der_.insert(cert.tbs_der_.end(), tbs_start, tbs_start + tbs_len);

        // Read signature value (OCTET STRING, tag 0x04)
        if (outer_cursor.ptr < outer_cursor.end) {
            cert.signature_ = outer_cursor.read_tlv_value(0x04);
        }
    } else {
        // Flat format
        TlvCursor cursor = outer_cursor;
        cert.tbs_der_ = der_bytes;

        auto name_bytes = cursor.read_tlv_value(0x0C);
        cert.subject_name_ = std::string(reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size());

        auto sub_bytes = cursor.read_tlv_value(0x04);
        if (sub_bytes.size() != 16) {
            return err<Certificate>(ErrorCode::CertificateInvalid, "subject_node_id must be 16 bytes");
        }
        std::copy(sub_bytes.begin(), sub_bytes.end(), cert.subject_.begin());

        auto iss_bytes = cursor.read_tlv_value(0x04);
        if (iss_bytes.size() != 16) {
            return err<Certificate>(ErrorCode::CertificateInvalid, "issuer_node_id must be 16 bytes");
        }
        std::copy(iss_bytes.begin(), iss_bytes.end(), cert.issuer_.begin());

        auto ts1 = cursor.read_tlv_value(0x02);
        cert.not_before_ms_ = read_u64(ByteSpan{ts1.data(), ts1.size()});

        auto ts2 = cursor.read_tlv_value(0x02);
        cert.not_after_ms_ = read_u64(ByteSpan{ts2.data(), ts2.size()});

        auto kt_bytes = cursor.read_tlv_value(0x02);
        if (!kt_bytes.empty()) {
            cert.key_type_ = static_cast<CertKeyType>(static_cast<std::uint8_t>(kt_bytes[0]));
        }

        if (has_key_type(cert.key_type_, CertKeyType::EcdsaP256)) {
            auto pk = cursor.read_tlv_value(0x04);
            if (pk.size() != 65) {
                return err<Certificate>(ErrorCode::CertificateInvalid, "ECDSA-P256 public key must be 65 bytes");
            }
            cert.ecdsa_pk_.data = std::move(pk);
        }

        if (has_key_type(cert.key_type_, CertKeyType::MlDsa65) ||
            has_key_type(cert.key_type_, CertKeyType::MlDsa44) ||
            has_key_type(cert.key_type_, CertKeyType::MlDsa87)) {
            auto pk = cursor.read_tlv_value(0x04);
            if (pk.empty()) {
                return err<Certificate>(ErrorCode::CertificateInvalid, "ML-DSA public key missing");
            }
            cert.ml_dsa_pk_.data = std::move(pk);
        }
    }

    UAV_PQC_LOG_DEBUG("identity.certificate", "Parsed cert subject='{}' key_type=0x{:02x} sig_len={}",
                      cert.subject_name_,
                      static_cast<std::uint8_t>(cert.key_type_),
                      cert.signature_.size());
    return ok<Certificate>(std::move(cert));
}

} // namespace uav_pqc::identity
