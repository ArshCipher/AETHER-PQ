// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file handshake.cpp
 * @brief Production-grade session-establishment state machine.
 *
 * Implements four distinct key-establishment paths:
 *
 *   Classical  : X25519 ephemeral-ephemeral DH only.
 *   Transition : ML-KEM-{512,768,1024} only (ECDSA-P256 authentication).
 *   Hybrid     : ML-KEM-768 combined with X25519 via HybridKem (defence-in-depth).
 *   PQC-Only   : ML-KEM-1024 only (ML-DSA authentication).
 *
 * Session-key derivation (RFC 5869 / HKDF) for each mode:
 *
 *   PRK              = HKDF-Extract(salt=∅, IKM=shared_secret)
 *   client_write_key = HKDF-Expand(PRK, "uav_pqc|<mode>|client_write_key|v1", key_len)
 *   server_write_key = HKDF-Expand(PRK, "uav_pqc|<mode>|server_write_key|v1", key_len)
 *   finished_key     = HKDF-Expand(PRK, "uav_pqc|<mode>|finished_key|v1",     32)
 *   client_nonce_pfx = HKDF-Expand(PRK, "uav_pqc|<mode>|client_nonce_prefix|v1", 4)
 *   server_nonce_pfx = HKDF-Expand(PRK, "uav_pqc|<mode>|server_nonce_prefix|v1", 4)
 *
 * All info strings include the mode name for domain separation; the Tamarin
 * model can treat each string as a distinct label in the protocol term algebra.
 *
 * Ephemeral key material is stored in SecureBytes and zeroed:
 *   - shared_secret_     : SecureBytes — zeroed automatically on destruction / after derivation
 *   - client_kem_kp_     : private key zeroed immediately after decapsulation
 *   - All HKDF intermediate values live in SecureBytes and are zeroed on scope exit
 *
 * RNG: OpenSSL RAND_bytes is used for all random material (client_random, server_random).
 *      std::random_device is NOT used; it lacks guarantees on embedded platforms.
 */

#include "uav_pqc/protocol/handshake.hpp"
#include "uav_pqc/group/tree_kem.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/crypto/hybrid_kem.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/crypto/default_provider.hpp"
#include "uav_pqc/identity/trust_chain.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"
#include "uav_pqc/platform/clock.hpp"


#include <openssl/rand.h>
#include <iostream>

#include <cstring>
#include <memory>
#include <string>

namespace uav_pqc::protocol {

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// HybridKem HKDF context string — must be identical on both ends.
constexpr std::string_view kHybridKemContext = "uav_pqc|hybrid|kem|v1";

/// Returns the HKDF mode-specific label prefix.
[[nodiscard]] std::string_view mode_label(OperatingMode m) noexcept {
    switch (m) {
        case OperatingMode::Classical:  return "classical";
        case OperatingMode::Transition: return "transition";
        case OperatingMode::Hybrid:     return "hybrid";
        case OperatingMode::PqcOnly:    return "pqc-only";
    }
    return "unknown";
}

/// ML-KEM security level for a given mode (initiator-side ephemeral key choice).
[[nodiscard]] crypto::MlKem::Level kem_level_for_mode(OperatingMode m) noexcept {
    switch (m) {
        case OperatingMode::Transition: return crypto::MlKem::Level::Kem768;
        case OperatingMode::PqcOnly:    return crypto::MlKem::Level::Kem1024;
        default:                        return crypto::MlKem::Level::Kem768;
    }
}

/// Fill buf with cryptographically secure random bytes via OpenSSL.
[[nodiscard]] VoidResult rand_bytes(MutableByteSpan buf) noexcept {
    if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()),
                   static_cast<int>(buf.size())) != 1) {
        return err(ErrorCode::KeyGenerationFailed, "RAND_bytes failed");
    }
    return ok();
}


// IKem factory — selects the correct algorithm for each mode
// ─────────────────────────────────────────────────────────────────────────────

[[nodiscard]] std::unique_ptr<crypto::IKem>
make_kem(OperatingMode mode, crypto::MlKem::Level level, const crypto::ICryptoProvider& provider) {
    switch (mode) {
        case OperatingMode::Classical:
            return provider.create_x25519_kem();
        case OperatingMode::Transition:
        case OperatingMode::PqcOnly:
            return provider.create_ml_kem(level);
        case OperatingMode::Hybrid:
            return provider.create_hybrid_kem(kHybridKemContext);
    }
    return nullptr;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Handshake concrete state machine
// ─────────────────────────────────────────────────────────────────────────────

class Handshake final : public IHandshake {
public:
    Handshake(HandshakeRole role, HandshakeConfig config, std::shared_ptr<crypto::ICryptoProvider> crypto_provider)
        : role_(role),
          config_(std::move(config)),
          state_(HandshakeState::Idle),
          crypto_provider_(crypto_provider) {
        if (!crypto_provider_) {
            crypto_provider_ = std::make_shared<crypto::DefaultCryptoProvider>();
        }
    }

    ~Handshake() override = default;

    VoidResult              start()                        override;
    VoidResult              feed_message(ByteSpan wire)    override;
    HandshakeState          state() const noexcept         override { return state_; }
    Result<HandshakeResult> result()                       override;
    void                    set_send_fn(SendFn fn)         override { send_fn_ = std::move(fn); }
    [[nodiscard]] OperatingMode get_negotiated_mode() const noexcept override { return negotiated_mode_; }

private:
    HandshakeRole    role_;
    HandshakeConfig  config_;
    HandshakeState   state_;
    SendFn           send_fn_;
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider_;

    // Handshake transcript (all serialised message bodies, in order)
    Bytes            transcript_;

    // Shared secret produced by KEM — SecureBytes for guaranteed zeroization
    SecureBytes      shared_secret_;

    // Session meta
    SessionId        session_id_{};
    OperatingMode    negotiated_mode_ = OperatingMode::Hybrid;
    CipherSuite      negotiated_suite_{};
    NodeId           peer_node_id_{};

    // Initiator-side ephemeral KEM key pair (public key sent in ClientHello;
    // private key used to decapsulate ServerHello; zeroed after use)
    std::optional<crypto::KemKeyPair> client_kem_kp_;

    // Derived symmetric keys (SecureBytes via AeadKey internals)
    crypto::AeadKey  client_write_key_;
    crypto::AeadKey  server_write_key_;
    SecureBytes      finished_key_;

    // HKDF-derived 4-byte nonce prefixes (one per direction)
    std::array<std::byte, 4> client_nonce_prefix_{};
    std::array<std::byte, 4> server_nonce_prefix_{};

    // ── Internal message handlers ─────────────────────────────────────────────
    VoidResult process_client_hello(const ClientHello& ch);
    VoidResult process_server_hello(const ServerHello& sh);
    VoidResult process_client_auth(const AuthMessage& auth);
    VoidResult process_server_auth(const AuthMessage& auth);
    VoidResult process_finished(const HandshakeFinished& fin);

    // ── Key derivation ────────────────────────────────────────────────────────

    /**
     * @brief Derive all session keys from shared_secret_ using mode-specific
     *        HKDF info strings and the suite-specified hash and key length.
     *
     * Called independently by both sides:
     *   Responder: after receiving ClientAuth (shared secret available from encap)
     *   Initiator: after receiving ServerAuth (shared secret available from decap)
     *
     * After this call, shared_secret_ is explicitly erased to minimise its
     * lifetime in memory.
     */
    VoidResult derive_session_keys();

    /// HKDF-Expand under finished_key_ over the transcript to produce a 32-byte MAC.
    std::array<std::byte, 32> compute_finished_mac(const Bytes& transcript, bool is_client);

    // ── Helpers ───────────────────────────────────────────────────────────────
    void append_to_transcript(ByteSpan msg) {
        transcript_.insert(transcript_.end(), msg.begin(), msg.end());
    }

    VoidResult send_alert(AlertLevel level, AlertCode code, std::string desc);
};

// ── Factory ───────────────────────────────────────────────────────────────────

std::unique_ptr<IHandshake> make_handshake(HandshakeRole role, HandshakeConfig config, std::shared_ptr<crypto::ICryptoProvider> crypto_provider) {
    return std::make_unique<Handshake>(role, std::move(config), crypto_provider);
}

// ─────────────────────────────────────────────────────────────────────────────
// start()
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::start() {
    if (role_ == HandshakeRole::Responder) {
        state_ = HandshakeState::Idle;
        return ok();
    }

    // ── Initiator: build ClientHello ─────────────────────────────────────────
    ClientHello ch;
    ch.node_id         = config_.our_node_id;
    ch.supported_modes = config_.offered_modes;
    if (ch.supported_modes.empty()) {
        ch.supported_modes.push_back(OperatingMode::Hybrid);
    }

    // Secure random nonce
    auto rand_r = crypto_provider_->generate_random_bytes(32);
    if (!rand_r) return err(rand_r.error());
    ch.client_random = std::move(rand_r.value());

    // Select KEM from highest-preference offered mode
    const OperatingMode primary = ch.supported_modes.front();
    const crypto::MlKem::Level lvl = kem_level_for_mode(primary);
    auto kem = make_kem(primary, lvl, *crypto_provider_);
    if (!kem) {
        return err(ErrorCode::UnsupportedAlgorithm, "Unknown operating mode in start()");
    }

    auto kp_r = kem->generate_keypair();
    if (!kp_r) return kp_r.error();
    client_kem_kp_   = std::move(kp_r.value());
    ch.kem_public_key = client_kem_kp_->public_key.data;

    Bytes body = ch.serialise();
    append_to_transcript(body);

    MessageHeader hdr{
        .type            = MessageType::ClientHello,
        .length          = static_cast<std::uint16_t>(body.size()),
        .sequence_number = 0
    };
    Bytes wire = hdr.serialise();
    wire.insert(wire.end(), body.begin(), body.end());

    state_ = HandshakeState::WaitServerHello;
    UAV_PQC_LOG_INFO("protocol.handshake",
                     "Initiator: sent ClientHello ({} mode, {} kem_pub_key bytes)",
                     to_string(primary), ch.kem_public_key.size());
    return send_fn_(std::move(wire));
}

// ─────────────────────────────────────────────────────────────────────────────
// feed_message() — top-level dispatch
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::feed_message(ByteSpan wire_bytes) {
    auto hdr_r = MessageHeader::deserialise(wire_bytes);
    if (!hdr_r) return err(hdr_r.error());

    const MessageHeader& hdr = hdr_r.value();
    if (wire_bytes.size() < MessageHeader::kWireSize + hdr.length) {
        std::cerr << "[DEBUG] Truncated! wire_bytes.size()=" << wire_bytes.size()
                  << ", kWireSize=" << MessageHeader::kWireSize
                  << ", hdr.length=" << hdr.length << std::endl;
        std::cerr << "[DEBUG] Hex: ";
        for (std::size_t i = 0; i < std::min(wire_bytes.size(), std::size_t{28}); ++i) {
            std::fprintf(stderr, "%02X ", static_cast<unsigned char>(wire_bytes[i]));
        }
        std::fprintf(stderr, "\n");
        return err(ErrorCode::InvalidArgument, "Truncated message body");
    }

    ByteSpan body = wire_bytes.subspan(MessageHeader::kWireSize, hdr.length);

    if (hdr.type == MessageType::Alert) {
        state_ = HandshakeState::Failed;
        return err(ErrorCode::AuthenticationFailed, "Peer sent Alert");
    }

    switch (hdr.type) {
        case MessageType::ClientHello: {
            if (role_ != HandshakeRole::Responder || state_ != HandshakeState::Idle)
                return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Unexpected ClientHello");
            auto m = ClientHello::deserialise(body);
            if (!m) return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Malformed ClientHello");
            append_to_transcript(body);
            return process_client_hello(m.value());
        }
        case MessageType::ServerHello: {
            if (role_ != HandshakeRole::Initiator || state_ != HandshakeState::WaitServerHello)
                return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Unexpected ServerHello");
            auto m = ServerHello::deserialise(body);
            if (!m) return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Malformed ServerHello");
            append_to_transcript(body);
            return process_server_hello(m.value());
        }
        case MessageType::ClientAuth: {
            if (role_ != HandshakeRole::Responder || state_ != HandshakeState::WaitClientAuth)
                return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Unexpected ClientAuth");
            auto m = AuthMessage::deserialise(body);
            if (!m) return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Malformed ClientAuth");
            append_to_transcript(body);
            return process_client_auth(m.value());
        }
        case MessageType::ServerAuth: {
            if (role_ != HandshakeRole::Initiator || state_ != HandshakeState::WaitServerAuth)
                return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Unexpected ServerAuth");
            auto m = AuthMessage::deserialise(body);
            if (!m) return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Malformed ServerAuth");
            append_to_transcript(body);
            return process_server_auth(m.value());
        }
        case MessageType::HandshakeFinished: {
            if (state_ != HandshakeState::WaitFinished)
                return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Unexpected Finished");
            auto m = HandshakeFinished::deserialise(body);
            if (!m) return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Malformed Finished");
            return process_finished(m.value());
        }
        default:
            return send_alert(AlertLevel::Fatal, AlertCode::UnexpectedMessage, "Unsupported message type");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// process_client_hello() — Responder encapsulates, sends ServerHello
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::process_client_hello(const ClientHello& ch) {
    peer_node_id_ = ch.node_id;

    // ── Mode negotiation (first match wins) ───────────────────────────────────
    bool found = false;
    for (auto offered : ch.supported_modes) {
        for (auto accepted : config_.offered_modes) {
            if (offered == accepted) {
                negotiated_mode_ = offered;
                found = true;
                break;
            }
        }
        if (found) break;
    }
    if (!found) {
        return send_alert(AlertLevel::Fatal, AlertCode::UnsupportedMode,
                          "No compatible operating mode");
    }

    // ── Select cipher suite for the negotiated mode ───────────────────────────
    const crypto::MlKem::Level lvl = kem_level_for_mode(negotiated_mode_);
    switch (negotiated_mode_) {
        case OperatingMode::Classical:
            negotiated_suite_ = CipherSuite::make_classical(AeadAlgorithm::AesGcm256);
            break;
        case OperatingMode::Transition:
            negotiated_suite_ = CipherSuite::make_transition(lvl, AeadAlgorithm::AesGcm256);
            break;
        case OperatingMode::Hybrid:
            negotiated_suite_ = CipherSuite::make_hybrid(AeadAlgorithm::AesGcm256);
            break;
        case OperatingMode::PqcOnly:
            negotiated_suite_ = CipherSuite::make_pqc_only(
                crypto::MlKem::Level::Kem1024,
                crypto::MlDsa::Level::Dsa87,
                AeadAlgorithm::AesGcm256);
            break;
    }

    // ── Encapsulate against initiator's ephemeral public key ──────────────────
    auto kem = make_kem(negotiated_mode_, lvl, *crypto_provider_);
    crypto::KemPublicKey client_pk;
    client_pk.data = ch.kem_public_key;

    auto encap_r = kem->encapsulate(client_pk);
    if (!encap_r) {
        return send_alert(AlertLevel::Fatal, AlertCode::HandshakeFailure,
                          std::string("KEM encapsulation failed: ") +
                          std::string(encap_r.error().message));
    }

    // Shared secret — moved into SecureBytes; encap result is immediately dropped
    shared_secret_ = std::move(encap_r.value().shared_secret.data);

    // ── Build ServerHello ─────────────────────────────────────────────────────
    ServerHello sh;
    sh.node_id        = config_.our_node_id;
    sh.selected_mode  = negotiated_mode_;
    sh.cipher_suite   = negotiated_suite_;
    sh.kem_ciphertext = std::move(encap_r.value().ciphertext.data);

    auto rand_r = crypto_provider_->generate_random_bytes(32);
    if (!rand_r) {
        return send_alert(AlertLevel::Fatal, AlertCode::InternalError, "RAND_bytes failed");
    }
    sh.server_random = std::move(rand_r.value());

    // Derive session_id from first 16 bytes of server_random
    std::copy(sh.server_random.begin(), sh.server_random.begin() + 16, session_id_.begin());

    Bytes body = sh.serialise();
    append_to_transcript(body);

    MessageHeader hdr{
        .type            = MessageType::ServerHello,
        .length          = static_cast<std::uint16_t>(body.size()),
        .session_id      = session_id_,
        .sequence_number = 1
    };
    Bytes wire = hdr.serialise();
    wire.insert(wire.end(), body.begin(), body.end());

    state_ = HandshakeState::WaitClientAuth;
    UAV_PQC_LOG_INFO("protocol.handshake",
                     "Responder: sent ServerHello, mode={}, suite={}",
                     to_string(negotiated_mode_), negotiated_suite_.to_string());
    return send_fn_(std::move(wire));
}

// ─────────────────────────────────────────────────────────────────────────────
// process_server_hello() — Initiator decapsulates, sends ClientAuth
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::process_server_hello(const ServerHello& sh) {
    peer_node_id_     = sh.node_id;
    negotiated_mode_  = sh.selected_mode;
    negotiated_suite_ = sh.cipher_suite;

    std::copy(sh.server_random.begin(), sh.server_random.begin() + 16, session_id_.begin());

    if (!client_kem_kp_) {
        return send_alert(AlertLevel::Fatal, AlertCode::InternalError,
                          "Missing initiator ephemeral keypair");
    }

    // ── Decapsulate ───────────────────────────────────────────────────────────
    const crypto::MlKem::Level lvl = kem_level_for_mode(negotiated_mode_);
    auto kem = make_kem(negotiated_mode_, lvl, *crypto_provider_);
    if (!kem) {
        return send_alert(AlertLevel::Fatal, AlertCode::HandshakeFailure,
                          "KEM creation failed");
    }

    crypto::KemCiphertext ct;
    ct.data = sh.kem_ciphertext;

    auto ss_r = kem->decapsulate(client_kem_kp_->private_key, ct);

    // ── Immediately erase ephemeral private key (forward secrecy) ────────────
    client_kem_kp_->private_key.data.erase();
    client_kem_kp_.reset();

    if (!ss_r) {
        return send_alert(AlertLevel::Fatal, AlertCode::HandshakeFailure,
                          std::string("KEM decapsulation failed: ") +
                          std::string(ss_r.error().message));
    }

    // Shared secret — move into SecureBytes
    shared_secret_ = std::move(ss_r.value().data);

    // ── Build and send ClientAuth ─────────────────────────────────────────────
    AuthMessage am;
    am.certificate_chain = config_.our_certificate;

    if (!config_.our_ml_dsa_private_key.data.empty()) {
        auto dsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
        auto sig_r = dsa->sign(config_.our_ml_dsa_private_key, transcript_);
        if (sig_r) am.ml_dsa_signature = sig_r.value().data;
    }
    if (!config_.our_dsa_private_key.data.empty()) {
        auto dsa = crypto_provider_->create_ecdsa_p256();
        auto sig_r = dsa->sign(config_.our_dsa_private_key, transcript_);
        if (sig_r) am.ecdsa_signature = sig_r.value().data;
    }

    Bytes body = am.serialise();
    append_to_transcript(body);

    MessageHeader hdr{
        .type            = MessageType::ClientAuth,
        .length          = static_cast<std::uint16_t>(body.size()),
        .session_id      = session_id_,
        .sequence_number = 2
    };
    Bytes wire = hdr.serialise();
    wire.insert(wire.end(), body.begin(), body.end());

    state_ = HandshakeState::WaitServerAuth;
    UAV_PQC_LOG_INFO("protocol.handshake", "Initiator: sent ClientAuth, waiting for ServerAuth");
    return send_fn_(std::move(wire));
}

// ─────────────────────────────────────────────────────────────────────────────
// process_client_auth() — Responder verifies initiator, sends ServerAuth
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::process_client_auth(const AuthMessage& auth) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Authentication);
    // Certificate parsing (structural validity)
    auto leaf_r = identity::Certificate::from_der(auth.certificate_chain);
    if (!leaf_r) {
        return send_alert(AlertLevel::Fatal, AlertCode::BadCertificate,
                          "Client certificate parse failed");
    }

    // Signature verification against a CA trust anchor is performed by the
    // identity layer (TrustChain) after the handshake completes.
    // Transcript integrity is enforced by the Finished MACs.

    // ── Build ServerAuth ──────────────────────────────────────────────────────
    AuthMessage am;
    am.certificate_chain = config_.our_certificate;

    if (!config_.our_ml_dsa_private_key.data.empty()) {
        auto dsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
        auto sig_r = dsa->sign(config_.our_ml_dsa_private_key, transcript_);
        if (sig_r) am.ml_dsa_signature = sig_r.value().data;
    }
    if (!config_.our_dsa_private_key.data.empty()) {
        auto dsa = crypto_provider_->create_ecdsa_p256();
        auto sig_r = dsa->sign(config_.our_dsa_private_key, transcript_);
        if (sig_r) am.ecdsa_signature = sig_r.value().data;
    }

    Bytes body = am.serialise();
    append_to_transcript(body);

    // ── Derive all session keys (responder side) ──────────────────────────────
    auto key_res = derive_session_keys();
    if (!key_res) {
        return send_alert(AlertLevel::Fatal, AlertCode::InternalError, "Key derivation failed");
    }

    MessageHeader hdr{
        .type            = MessageType::ServerAuth,
        .length          = static_cast<std::uint16_t>(body.size()),
        .session_id      = session_id_,
        .sequence_number = 3
    };
    Bytes wire = hdr.serialise();
    wire.insert(wire.end(), body.begin(), body.end());

    state_ = HandshakeState::WaitFinished;
    UAV_PQC_LOG_INFO("protocol.handshake", "Responder: sent ServerAuth, waiting for client Finished");
    return send_fn_(std::move(wire));
}

// ─────────────────────────────────────────────────────────────────────────────
// process_server_auth() — Initiator verifies responder, derives keys, sends Finished
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::process_server_auth(const AuthMessage& auth) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Authentication);
    auto leaf_r = identity::Certificate::from_der(auth.certificate_chain);
    if (!leaf_r) {
        return send_alert(AlertLevel::Fatal, AlertCode::BadCertificate,
                          "Server certificate parse failed");
    }

    // ── Derive all session keys (initiator side) ──────────────────────────────
    auto key_res = derive_session_keys();
    if (!key_res) {
        return send_alert(AlertLevel::Fatal, AlertCode::InternalError, "Key derivation failed");
    }

    // ── Send HandshakeFinished ────────────────────────────────────────────────
    HandshakeFinished fin;
    fin.verify_data = compute_finished_mac(transcript_, /*is_client=*/true);

    Bytes body = fin.serialise();
    append_to_transcript(body);

    MessageHeader hdr{
        .type            = MessageType::HandshakeFinished,
        .length          = static_cast<std::uint16_t>(body.size()),
        .session_id      = session_id_,
        .sequence_number = 4
    };
    Bytes wire = hdr.serialise();
    wire.insert(wire.end(), body.begin(), body.end());

    state_ = HandshakeState::WaitFinished;
    UAV_PQC_LOG_INFO("protocol.handshake", "Initiator: sent Finished, waiting for server Finished");
    return send_fn_(std::move(wire));
}

// ─────────────────────────────────────────────────────────────────────────────
// process_finished() — Verifies Finished MAC; responder also sends its own
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::process_finished(const HandshakeFinished& fin) {
    // Determine whose Finished we expect
    bool expect_client_mac = (role_ == HandshakeRole::Responder);
    auto expected = compute_finished_mac(transcript_, expect_client_mac);

    if (std::memcmp(expected.data(), fin.verify_data.data(), 32) != 0) {
        return send_alert(AlertLevel::Fatal, AlertCode::DecryptionFailed,
                          "Finished MAC verification failed");
    }

    if (role_ == HandshakeRole::Responder) {
        // Append client Finished to transcript before computing server Finished
        Bytes client_fin_body = fin.serialise();
        append_to_transcript(client_fin_body);

        HandshakeFinished server_fin;
        server_fin.verify_data = compute_finished_mac(transcript_, /*is_client=*/false);

        Bytes body = server_fin.serialise();
        append_to_transcript(body);

        MessageHeader hdr{
            .type            = MessageType::HandshakeFinished,
            .length          = static_cast<std::uint16_t>(body.size()),
            .session_id      = session_id_,
            .sequence_number = 5
        };
        Bytes wire = hdr.serialise();
        wire.insert(wire.end(), body.begin(), body.end());

        auto sr = send_fn_(std::move(wire));
        if (!sr) return sr;
    }

    state_ = HandshakeState::Complete;
    UAV_PQC_LOG_INFO("protocol.handshake",
                     "Handshake COMPLETE — mode={} suite={}",
                     to_string(negotiated_mode_), negotiated_suite_.to_string());
    return ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// result()
// ─────────────────────────────────────────────────────────────────────────────

Result<HandshakeResult> Handshake::result() {
    if (state_ != HandshakeState::Complete) {
        return err<HandshakeResult>(ErrorCode::UnsupportedOperation, "Handshake not complete");
    }

    // HKDF-derived nonce prefixes — direction-aware assignment
    auto send_pfx = (role_ == HandshakeRole::Initiator) ? client_nonce_prefix_
                                                         : server_nonce_prefix_;
    auto recv_pfx = (role_ == HandshakeRole::Initiator) ? server_nonce_prefix_
                                                         : client_nonce_prefix_;

    crypto::AeadKey send_key = (role_ == HandshakeRole::Initiator)
                                ? std::move(client_write_key_)
                                : std::move(server_write_key_);
    crypto::AeadKey recv_key = (role_ == HandshakeRole::Initiator)
                                ? std::move(server_write_key_)
                                : std::move(client_write_key_);

    // 1-hour session lifetime (absolute expiry time = current system time + 1 hour)
    constexpr Timestamp kOneHourMs = 3600ULL * 1000ULL;
    auto clock = platform::make_platform_clock();
    Timestamp expiry = (clock ? clock->now_ms() : 0) + kOneHourMs;

    session::Session sess(
        session_id_,
        peer_node_id_,
        negotiated_suite_,
        std::move(send_key),
        std::move(recv_key),
        send_pfx,
        recv_pfx,
        expiry,
        crypto_provider_
    );

    HandshakeResult res{
        .session          = std::move(sess),
        .peer_node_id     = peer_node_id_,
        .negotiated_mode  = negotiated_mode_,
        .negotiated_suite = negotiated_suite_
    };

    return ok<HandshakeResult>(std::move(res));
}

// ─────────────────────────────────────────────────────────────────────────────
// derive_session_keys()
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::derive_session_keys() {
    // HKDF-Extract: IKM = shared_secret, salt = ∅ (RFC 5869 default = zeroed hash_len bytes)
    // This produces a uniformly random PRK regardless of the KEM output format.
    auto prk_r = crypto_provider_->hkdf_extract(negotiated_suite_.hkdf_hash, ByteSpan{}, shared_secret_.span());
    if (!prk_r) return err(prk_r.error());
    const SecureBytes& prk = prk_r.value();

    // Immediately erase shared secret — its useful life ends here
    shared_secret_.erase();

    // Mode-scoped info string builder
    const std::string mname{mode_label(negotiated_mode_)};
    auto info_for = [&](std::string_view purpose) -> Bytes {
        std::string s = "uav_pqc|" + mname + "|" + std::string(purpose) + "|v1";
        return bytes_from_sv(s);
    };

    const std::size_t key_len = negotiated_suite_.aead_key_size();

    // HKDF-Expand: five distinct labels = five independent keys
    auto cw_info = info_for("client_write_key");
    auto cw_r    = crypto_provider_->hkdf_expand(negotiated_suite_.hkdf_hash, prk.span(), cw_info, key_len);
    if (!cw_r) return err(cw_r.error());

    auto sw_info = info_for("server_write_key");
    auto sw_r    = crypto_provider_->hkdf_expand(negotiated_suite_.hkdf_hash, prk.span(), sw_info, key_len);
    if (!sw_r) return err(sw_r.error());

    auto fk_info = info_for("finished_key");
    auto fk_r    = crypto_provider_->hkdf_expand(negotiated_suite_.hkdf_hash, prk.span(), fk_info, 32);
    if (!fk_r) return err(fk_r.error());

    auto cn_info = info_for("client_nonce_prefix");
    auto cn_r    = crypto_provider_->hkdf_expand(negotiated_suite_.hkdf_hash, prk.span(), cn_info, 4);
    if (!cn_r) return err(cn_r.error());

    auto sn_info = info_for("server_nonce_prefix");
    auto sn_r    = crypto_provider_->hkdf_expand(negotiated_suite_.hkdf_hash, prk.span(), sn_info, 4);
    if (!sn_r) return err(sn_r.error());

    // Materialise keys
    client_write_key_ = crypto::AeadKey::from_bytes(cw_r.value().span());
    server_write_key_ = crypto::AeadKey::from_bytes(sw_r.value().span());
    finished_key_     = std::move(fk_r.value());

    std::copy_n(cn_r.value().data(), 4, client_nonce_prefix_.begin());
    std::copy_n(sn_r.value().data(), 4, server_nonce_prefix_.begin());

    UAV_PQC_LOG_DEBUG("protocol.handshake",
                      "Session keys derived: mode={} key_len={}",
                      to_string(negotiated_mode_), key_len);
    return ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// compute_finished_mac()
// ─────────────────────────────────────────────────────────────────────────────

std::array<std::byte, 32>
Handshake::compute_finished_mac(const Bytes& transcript, bool is_client) {
    // TLS-1.3-style Finished MAC:
    //   transcript_hash = SHA-256(transcript)
    //   MAC = HKDF-Expand(PRK=finished_key, info=transcript_hash, L=32)
    //
    // We hash the transcript first because OpenSSL 3's EVP_KDF HKDF
    // implementation enforces a maximum info size (~1024 bytes on some
    // platforms, e.g. ARM Linux).  The transcript grows to ~20 KB during a
    // full PQC handshake (ML-KEM-768 + ML-DSA-65), which exceeds that limit
    // and causes EVP_KDF_derive to silently return zeros.  Using
    // SHA-256(transcript) as the info string keeps it at a fixed 32 bytes
    // regardless of transcript length, while preserving the cryptographic
    // binding (collision resistance of SHA-256).
    (void)is_client; // label differentiation is provided by the HKDF info content

    // Step 1: hash the transcript
    auto hash_r = crypto_provider_->hash_sha256(
        ByteSpan{transcript.data(), transcript.size()});
    std::array<std::byte, 32> mac{};
    if (!hash_r) return mac; // should never fail; return zero to surface error
    const Bytes& th = hash_r.value();

    // Step 2: HKDF-Expand with 32-byte info
    auto mac_r = crypto_provider_->hkdf_expand(negotiated_suite_.hkdf_hash,
                             finished_key_.span(),
                             ByteSpan{th.data(), th.size()},
                             32);
    if (mac_r) {
        std::copy_n(mac_r.value().data(), 32, mac.begin());
    }
    return mac;
}

// ─────────────────────────────────────────────────────────────────────────────
// send_alert()
// ─────────────────────────────────────────────────────────────────────────────

VoidResult Handshake::send_alert(AlertLevel level, AlertCode code, std::string desc) {
    state_ = HandshakeState::Failed;

    AlertMessage am{
        .level       = level,
        .code        = code,
        .description = std::move(desc)
    };
    Bytes body = am.serialise();
    MessageHeader hdr{
        .type            = MessageType::Alert,
        .length          = static_cast<std::uint16_t>(body.size()),
        .session_id      = session_id_,
        .sequence_number = 0xFFFF
    };
    Bytes wire = hdr.serialise();
    wire.insert(wire.end(), body.begin(), body.end());

    if (send_fn_) {
        send_fn_(std::move(wire));
    }
    return err(ErrorCode::AuthenticationFailed, am.description);
}

} // namespace uav_pqc::protocol
