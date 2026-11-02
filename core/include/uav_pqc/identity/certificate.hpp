// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file certificate.hpp
 * @brief Certificate types for the UAV-PQC identity layer.
 *
 * Certificates are structured credentials binding a NodeId to one or more
 * public keys (classical ECDSA-P256 and/or post-quantum ML-DSA).  They are
 * issued by the Certificate Authority (CA) and used for mutual authentication
 * during the handshake.
 *
 * The certificate format is a simplified DER-like TLV structure (not full X.509)
 * to reduce parsing complexity on embedded targets.  A separate tool in tools/
 * can convert to/from X.509 for interoperability with classical PKI.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/dsa.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace uav_pqc::identity {

/**
 * @brief Supported certificate key types (bitmask; a certificate may carry both).
 */
enum class CertKeyType : std::uint8_t {
    None         = 0x00,
    EcdsaP256    = 0x01, ///< Classical ECDSA over P-256
    MlDsa44      = 0x02, ///< ML-DSA-44 (Lightweight)
    MlDsa65      = 0x04, ///< ML-DSA-65 (Standard)
    MlDsa87      = 0x08, ///< ML-DSA-87 (Hardened)
    Hybrid       = 0x05, ///< ECDSA-P256 + ML-DSA-65 (most common hybrid)
};

[[nodiscard]] inline CertKeyType operator|(CertKeyType a, CertKeyType b) noexcept {
    return static_cast<CertKeyType>(
        static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b));
}
[[nodiscard]] inline bool has_key_type(CertKeyType flags, CertKeyType t) noexcept {
    return (static_cast<std::uint8_t>(flags) & static_cast<std::uint8_t>(t)) != 0u;
}

/**
 * @brief A parsed UAV-PQC certificate.
 *
 * Immutable after construction.  The raw DER bytes are retained for
 * signature verification; parsed fields are extracted for fast lookup.
 */
class Certificate {
public:
    Certificate() = default;
    ~Certificate() = default;
    Certificate(const Certificate&)            = default;
    Certificate& operator=(const Certificate&) = default;
    Certificate(Certificate&&) noexcept        = default;
    Certificate& operator=(Certificate&&) noexcept = default;

    // ── Deserialization ────────────────────────────────────────────────────────

    /**
     * @brief Parse a certificate from its raw DER bytes.
     *
     * @return Populated Certificate, or ErrorCode::CertificateInvalid.
     */
    [[nodiscard]] static Result<Certificate> from_der(Bytes der_bytes);

    // ── Field accessors ───────────────────────────────────────────────────────

    [[nodiscard]] const NodeId&              subject_node_id()    const noexcept { return subject_; }
    [[nodiscard]] const NodeId&              issuer_node_id()     const noexcept { return issuer_; }
    [[nodiscard]] const std::string&         subject_name()       const noexcept { return subject_name_; }
    [[nodiscard]] Timestamp                  not_before_ms()      const noexcept { return not_before_ms_; }
    [[nodiscard]] Timestamp                  not_after_ms()       const noexcept { return not_after_ms_; }
    [[nodiscard]] CertKeyType                key_type()           const noexcept { return key_type_; }
    [[nodiscard]] const crypto::DsaPublicKey& ecdsa_public_key()  const noexcept { return ecdsa_pk_; }
    [[nodiscard]] const crypto::DsaPublicKey& ml_dsa_public_key() const noexcept { return ml_dsa_pk_; }
    [[nodiscard]] const Bytes&               raw_der()            const noexcept { return raw_der_; }
    [[nodiscard]] const Bytes&               tbs_der()            const noexcept { return tbs_der_; }
    [[nodiscard]] const Bytes&               signature()          const noexcept { return signature_; }

    // ── Validity checks ────────────────────────────────────────────────────────

    [[nodiscard]] bool is_expired(Timestamp now_ms)   const noexcept { return now_ms > not_after_ms_; }
    [[nodiscard]] bool is_valid_at(Timestamp now_ms)  const noexcept {
        return now_ms >= not_before_ms_ && now_ms <= not_after_ms_;
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    [[nodiscard]] const Bytes& to_der() const noexcept { return raw_der_; }

private:
    NodeId               subject_{};
    NodeId               issuer_{};
    std::string          subject_name_;
    Timestamp            not_before_ms_ = 0;
    Timestamp            not_after_ms_  = 0;
    CertKeyType          key_type_      = CertKeyType::None;
    crypto::DsaPublicKey ecdsa_pk_;
    crypto::DsaPublicKey ml_dsa_pk_;
    Bytes                raw_der_;
    Bytes                tbs_der_;
    Bytes                signature_;
};

} // namespace uav_pqc::identity
