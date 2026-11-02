// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/identity/certificate.hpp"
#include "uav_pqc/session/session.hpp"
#include "uav_pqc/protocol/handshake.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <memory>

namespace uav_pqc::crypto { class ICryptoProvider; }

namespace uav_pqc::protocol {

enum class AuthRejectReason : std::uint32_t {
    Unknown             = 0,
    InvalidSignature    = 1,
    ExpiredTimestamp    = 2,
    ReplayDetected      = 3,
    InvalidCertificate  = 4,
    DecapsulationFailed = 5,
};

/**
 * @brief AUTH_REQ structure
 */
struct AuthReq {
    NodeId                  node_id{};
    identity::Certificate   cert;
    Bytes                   kem_pub;
    Bytes                   u_nonce;
    Timestamp               timestamp = 0;
    Bytes                   signature;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<AuthReq> deserialise(ByteSpan data);
    [[nodiscard]] Bytes get_to_be_signed_bytes() const;
};

/**
 * @brief AUTH_CHALLENGE structure
 */
struct AuthChallenge {
    NodeId                  node_id{};
    identity::Certificate   cert;
    Bytes                   g_nonce;
    Bytes                   u_nonce;
    Timestamp               timestamp = 0;
    Bytes                   signature;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<AuthChallenge> deserialise(ByteSpan data);
    [[nodiscard]] Bytes get_to_be_signed_bytes() const;
};

/**
 * @brief AUTH_RESPONSE structure
 */
struct AuthResponse {
    Bytes                   u_nonce;
    Bytes                   g_nonce;
    Timestamp               timestamp = 0;
    Bytes                   signature;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<AuthResponse> deserialise(ByteSpan data);
    [[nodiscard]] Bytes get_to_be_signed_bytes() const;
};

/**
 * @brief AUTH_SUCCESS structure
 */
struct AuthSuccess {
    Bytes                   g_nonce;
    Bytes                   kem_ciphertext;
    Timestamp               timestamp = 0;
    Bytes                   signature;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<AuthSuccess> deserialise(ByteSpan data);
    [[nodiscard]] Bytes get_to_be_signed_bytes() const;
};

/**
 * @brief AUTH_FAIL structure
 */
struct AuthFail {
    Bytes                   nonce;
    AuthRejectReason        reason = AuthRejectReason::Unknown;
    std::string             description;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<AuthFail> deserialise(ByteSpan data);
};

struct AuthResult {
    session::Session   session;
    NodeId             peer_node_id;
};

/**
 * @brief UAV side Mutual Authentication initiator
 */
class UavAuthInitiator {
public:
    UavAuthInitiator(
        identity::Certificate our_cert,
        const crypto::DsaKeyPair& our_ml_dsa_key,
        identity::Certificate ca_anchor,
        std::shared_ptr<platform::IClock> clock = nullptr,
        std::shared_ptr<crypto::ICryptoProvider> provider = nullptr);
    ~UavAuthInitiator() = default;

    Result<Bytes> initiate(Timestamp now_ms = 0);
    Result<Bytes> handle_challenge(ByteSpan challenge_msg, Timestamp now_ms = 0);
    VoidResult handle_success(ByteSpan success_msg, Timestamp now_ms = 0);

    [[nodiscard]] HandshakeState state() const noexcept { return state_; }
    [[nodiscard]] Result<AuthResult> result();

private:
    HandshakeState state_ = HandshakeState::Idle;
    identity::Certificate our_cert_;
    crypto::DsaKeyPair our_ml_dsa_key_;
    identity::Certificate ca_anchor_;

    Bytes sent_nonce_;
    Bytes received_nonce_;
    NodeId peer_node_id_{};
    crypto::DsaPublicKey peer_dsa_pub_;
    SessionId session_id_{};
    
    // KEM ephemeral context
    crypto::KemKeyPair kem_kp_;
    Bytes shared_secret_;
    
    std::optional<AuthResult> result_;
    std::shared_ptr<platform::IClock> clock_;
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider_;
};

/**
 * @brief GCS side Mutual Authentication responder
 */
class GcsAuthResponder {
public:
    GcsAuthResponder(
        identity::Certificate our_cert,
        const crypto::DsaKeyPair& our_ml_dsa_key,
        identity::Certificate ca_anchor,
        std::shared_ptr<platform::IClock> clock = nullptr,
        std::shared_ptr<crypto::ICryptoProvider> provider = nullptr);
    ~GcsAuthResponder() = default;

    Result<Bytes> handle_req(ByteSpan req_msg, Timestamp now_ms = 0);
    Result<Bytes> handle_response(ByteSpan response_msg, Timestamp now_ms = 0);

    [[nodiscard]] HandshakeState state() const noexcept { return state_; }
    [[nodiscard]] Result<AuthResult> result();

private:
    HandshakeState state_ = HandshakeState::Idle;
    identity::Certificate our_cert_;
    crypto::DsaKeyPair our_ml_dsa_key_;
    identity::Certificate ca_anchor_;

    Bytes sent_nonce_;
    Bytes received_nonce_;
    NodeId peer_node_id_{};
    crypto::DsaPublicKey peer_dsa_pub_;
    SessionId session_id_{};

    // Peer KEM public key
    Bytes peer_kem_pub_;
    Bytes shared_secret_;

    std::optional<AuthResult> result_;
    
    // Timestamp/replay tracking for GCS
    std::vector<Bytes> seen_nonces_;
    std::shared_ptr<platform::IClock> clock_;
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider_;
};

} // namespace uav_pqc::protocol
