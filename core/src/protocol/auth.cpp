// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/protocol/auth.hpp"
#include "uav_pqc/protocol/message.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/identity/trust_chain.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/crypto/default_provider.hpp"
#include <cstring>
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

crypto::DsaKeyPair clone_keypair(const crypto::DsaKeyPair& kp) {
    crypto::DsaKeyPair copy;
    copy.public_key = kp.public_key;
    Bytes bytes_copy(kp.private_key.data.bytes().begin(), kp.private_key.data.bytes().end());
    copy.private_key.data = SecureBytes(std::move(bytes_copy));
    return copy;
}

VoidResult derive_session_keys(
    ByteSpan shared_secret,
    HandshakeRole role,
    SessionId session_id,
    NodeId peer_node_id,
    crypto::AeadKey& send_key,
    crypto::AeadKey& recv_key,
    std::array<std::byte, 4>& send_prefix,
    std::array<std::byte, 4>& recv_prefix) {
    
    crypto::Hkdf hkdf(crypto::HkdfHash::Sha256);
    auto master_secret_r = hkdf.extract(ByteSpan{}, shared_secret);
    if (!master_secret_r) return err(master_secret_r.error());

    const auto client_info = Bytes{std::byte{'c'}, std::byte{'l'}, std::byte{'i'}, std::byte{'e'}, std::byte{'n'}, std::byte{'t'}, std::byte{' '}, std::byte{'k'}, std::byte{'e'}, std::byte{'y'}};
    auto cw_r = hkdf.expand(master_secret_r.value().span(), ByteSpan{client_info.data(), client_info.size()}, 32);
    if (!cw_r) return err(cw_r.error());

    const auto server_info = Bytes{std::byte{'s'}, std::byte{'e'}, std::byte{'r'}, std::byte{'v'}, std::byte{'e'}, std::byte{'r'}, std::byte{' '}, std::byte{'k'}, std::byte{'e'}, std::byte{'y'}};
    auto sw_r = hkdf.expand(master_secret_r.value().span(), ByteSpan{server_info.data(), server_info.size()}, 32);
    if (!sw_r) return err(sw_r.error());

    const auto client_iv_info = Bytes{std::byte{'c'}, std::byte{'l'}, std::byte{'i'}, std::byte{'e'}, std::byte{'n'}, std::byte{'t'}, std::byte{' '}, std::byte{'i'}, std::byte{'v'}};
    auto civ_r = hkdf.expand(master_secret_r.value().span(), ByteSpan{client_iv_info.data(), client_iv_info.size()}, 4);
    if (!civ_r) return err(civ_r.error());

    const auto server_iv_info = Bytes{std::byte{'s'}, std::byte{'e'}, std::byte{'r'}, std::byte{'v'}, std::byte{'e'}, std::byte{'r'}, std::byte{' '}, std::byte{'i'}, std::byte{'v'}};
    auto siv_r = hkdf.expand(master_secret_r.value().span(), ByteSpan{server_iv_info.data(), server_iv_info.size()}, 4);
    if (!siv_r) return err(siv_r.error());

    send_prefix = std::array<std::byte, 4>{};
    recv_prefix = std::array<std::byte, 4>{};

    if (role == HandshakeRole::Initiator) {
        send_key = crypto::AeadKey::from_bytes(cw_r.value().span());
        recv_key = crypto::AeadKey::from_bytes(sw_r.value().span());
        std::copy(civ_r.value().bytes().begin(), civ_r.value().bytes().end(), send_prefix.begin());
        std::copy(siv_r.value().bytes().begin(), siv_r.value().bytes().end(), recv_prefix.begin());
    } else {
        send_key = crypto::AeadKey::from_bytes(sw_r.value().span());
        recv_key = crypto::AeadKey::from_bytes(cw_r.value().span());
        std::copy(siv_r.value().bytes().begin(), siv_r.value().bytes().end(), send_prefix.begin());
        std::copy(civ_r.value().bytes().begin(), civ_r.value().bytes().end(), recv_prefix.begin());
    }
    return ok();
}

CipherSuite default_cipher_suite() {
    return CipherSuite::make_pqc_only(
        crypto::MlKem::Level::Kem768,
        crypto::MlDsa::Level::Dsa65,
        AeadAlgorithm::AesGcm256
    );
}

} // namespace

// ── AuthReq ──────────────────────────────────────────────────────────────────

Bytes AuthReq::get_to_be_signed_bytes() const {
    Bytes out;
    out.insert(out.end(), node_id.begin(), node_id.end());
    append_len16_bytes(out, cert.raw_der());
    append_len16_bytes(out, kem_pub);
    append_len16_bytes(out, u_nonce);
    
    std::byte ts_buf[8];
    write_u64_be(ts_buf, timestamp);
    out.insert(out.end(), ts_buf, ts_buf + 8);
    return out;
}

Bytes AuthReq::serialise() const {
    Bytes out = get_to_be_signed_bytes();
    append_len16_bytes(out, signature);
    return out;
}

Result<AuthReq> AuthReq::deserialise(ByteSpan data) {
    if (data.size() < 32) {
        return err<AuthReq>(ErrorCode::InvalidArgument, "Data too short for AuthReq");
    }
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();
    
    AuthReq req;
    std::copy(ptr, ptr + 32, req.node_id.begin());
    ptr += 32;
    
    auto cert_der_r = read_len16_bytes(ptr, end);
    if (!cert_der_r) return err<AuthReq>(cert_der_r.error());
    auto cert_r = identity::Certificate::from_der(std::move(cert_der_r.value()));
    if (!cert_r) return err<AuthReq>(cert_r.error());
    req.cert = std::move(cert_r.value());
    
    auto kem_r = read_len16_bytes(ptr, end);
    if (!kem_r) return err<AuthReq>(kem_r.error());
    req.kem_pub = std::move(kem_r.value());
    
    auto nonce_r = read_len16_bytes(ptr, end);
    if (!nonce_r) return err<AuthReq>(nonce_r.error());
    req.u_nonce = std::move(nonce_r.value());
    
    if (ptr + 8 > end) return err<AuthReq>(ErrorCode::InvalidArgument, "Truncated timestamp");
    req.timestamp = read_u64_be(ptr);
    ptr += 8;
    
    auto sig_r = read_len16_bytes(ptr, end);
    if (!sig_r) return err<AuthReq>(sig_r.error());
    req.signature = std::move(sig_r.value());
    
    return ok<AuthReq>(std::move(req));
}

// ── AuthChallenge ────────────────────────────────────────────────────────────

Bytes AuthChallenge::get_to_be_signed_bytes() const {
    Bytes out;
    out.insert(out.end(), node_id.begin(), node_id.end());
    append_len16_bytes(out, cert.raw_der());
    append_len16_bytes(out, g_nonce);
    append_len16_bytes(out, u_nonce);
    
    std::byte ts_buf[8];
    write_u64_be(ts_buf, timestamp);
    out.insert(out.end(), ts_buf, ts_buf + 8);
    return out;
}

Bytes AuthChallenge::serialise() const {
    Bytes out = get_to_be_signed_bytes();
    append_len16_bytes(out, signature);
    return out;
}

Result<AuthChallenge> AuthChallenge::deserialise(ByteSpan data) {
    if (data.size() < 32) return err<AuthChallenge>(ErrorCode::InvalidArgument, "Data too short");
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();
    
    AuthChallenge ch;
    std::copy(ptr, ptr + 32, ch.node_id.begin());
    ptr += 32;
    
    auto cert_der_r = read_len16_bytes(ptr, end);
    if (!cert_der_r) return err<AuthChallenge>(cert_der_r.error());
    auto cert_r = identity::Certificate::from_der(std::move(cert_der_r.value()));
    if (!cert_r) return err<AuthChallenge>(cert_r.error());
    ch.cert = std::move(cert_r.value());
    
    auto g_nonce_r = read_len16_bytes(ptr, end);
    if (!g_nonce_r) return err<AuthChallenge>(g_nonce_r.error());
    ch.g_nonce = std::move(g_nonce_r.value());
    
    auto u_nonce_r = read_len16_bytes(ptr, end);
    if (!u_nonce_r) return err<AuthChallenge>(u_nonce_r.error());
    ch.u_nonce = std::move(u_nonce_r.value());
    
    if (ptr + 8 > end) return err<AuthChallenge>(ErrorCode::InvalidArgument, "Truncated timestamp");
    ch.timestamp = read_u64_be(ptr);
    ptr += 8;
    
    auto sig_r = read_len16_bytes(ptr, end);
    if (!sig_r) return err<AuthChallenge>(sig_r.error());
    ch.signature = std::move(sig_r.value());
    
    return ok<AuthChallenge>(std::move(ch));
}

// ── AuthResponse ─────────────────────────────────────────────────────────────

Bytes AuthResponse::get_to_be_signed_bytes() const {
    Bytes out;
    append_len16_bytes(out, u_nonce);
    append_len16_bytes(out, g_nonce);
    std::byte ts_buf[8];
    write_u64_be(ts_buf, timestamp);
    out.insert(out.end(), ts_buf, ts_buf + 8);
    return out;
}

Bytes AuthResponse::serialise() const {
    Bytes out = get_to_be_signed_bytes();
    append_len16_bytes(out, signature);
    return out;
}

Result<AuthResponse> AuthResponse::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();
    
    auto u_nonce_r = read_len16_bytes(ptr, end);
    if (!u_nonce_r) return err<AuthResponse>(u_nonce_r.error());
    
    auto g_nonce_r = read_len16_bytes(ptr, end);
    if (!g_nonce_r) return err<AuthResponse>(g_nonce_r.error());
    
    if (ptr + 8 > end) return err<AuthResponse>(ErrorCode::InvalidArgument, "Truncated timestamp");
    Timestamp ts = read_u64_be(ptr);
    ptr += 8;
    
    auto sig_r = read_len16_bytes(ptr, end);
    if (!sig_r) return err<AuthResponse>(sig_r.error());
    
    AuthResponse resp;
    resp.u_nonce = std::move(u_nonce_r.value());
    resp.g_nonce = std::move(g_nonce_r.value());
    resp.timestamp = ts;
    resp.signature = std::move(sig_r.value());
    
    return ok<AuthResponse>(std::move(resp));
}

// ── AuthSuccess ──────────────────────────────────────────────────────────────

Bytes AuthSuccess::get_to_be_signed_bytes() const {
    Bytes out;
    append_len16_bytes(out, g_nonce);
    append_len16_bytes(out, kem_ciphertext);
    std::byte ts_buf[8];
    write_u64_be(ts_buf, timestamp);
    out.insert(out.end(), ts_buf, ts_buf + 8);
    return out;
}

Bytes AuthSuccess::serialise() const {
    Bytes out = get_to_be_signed_bytes();
    append_len16_bytes(out, signature);
    return out;
}

Result<AuthSuccess> AuthSuccess::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();
    
    auto g_nonce_r = read_len16_bytes(ptr, end);
    if (!g_nonce_r) return err<AuthSuccess>(g_nonce_r.error());
    
    auto kem_ct_r = read_len16_bytes(ptr, end);
    if (!kem_ct_r) return err<AuthSuccess>(kem_ct_r.error());
    
    if (ptr + 8 > end) return err<AuthSuccess>(ErrorCode::InvalidArgument, "Truncated timestamp");
    Timestamp ts = read_u64_be(ptr);
    ptr += 8;
    
    auto sig_r = read_len16_bytes(ptr, end);
    if (!sig_r) return err<AuthSuccess>(sig_r.error());
    
    AuthSuccess succ;
    succ.g_nonce = std::move(g_nonce_r.value());
    succ.kem_ciphertext = std::move(kem_ct_r.value());
    succ.timestamp = ts;
    succ.signature = std::move(sig_r.value());
    
    return ok<AuthSuccess>(std::move(succ));
}

// ── AuthFail ─────────────────────────────────────────────────────────────────

Bytes AuthFail::serialise() const {
    Bytes out;
    append_len16_bytes(out, nonce);
    
    std::byte res_buf[4];
    write_u32_be(res_buf, static_cast<std::uint32_t>(reason));
    out.insert(out.end(), res_buf, res_buf + 4);
    
    append_len16_string(out, description);
    return out;
}

Result<AuthFail> AuthFail::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();
    
    auto nonce_r = read_len16_bytes(ptr, end);
    if (!nonce_r) return err<AuthFail>(nonce_r.error());
    
    if (ptr + 4 > end) return err<AuthFail>(ErrorCode::InvalidArgument, "Truncated reason");
    std::uint32_t reason_val = read_u32_be(ptr);
    ptr += 4;
    
    auto desc_r = read_len16_string(ptr, end);
    if (!desc_r) return err<AuthFail>(desc_r.error());
    
    AuthFail fail;
    fail.nonce = std::move(nonce_r.value());
    fail.reason = static_cast<AuthRejectReason>(reason_val);
    fail.description = std::move(desc_r.value());
    
    return ok<AuthFail>(std::move(fail));
}

// ── UavAuthInitiator ──────────────────────────────────────────────────────────

UavAuthInitiator::UavAuthInitiator(
    identity::Certificate our_cert,
    const crypto::DsaKeyPair& our_ml_dsa_key,
    identity::Certificate ca_anchor,
    std::shared_ptr<platform::IClock> clock,
    std::shared_ptr<crypto::ICryptoProvider> provider)
    : our_cert_(std::move(our_cert)),
      our_ml_dsa_key_(clone_keypair(our_ml_dsa_key)),
      ca_anchor_(std::move(ca_anchor)),
      clock_(clock),
      crypto_provider_(std::move(provider)) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    if (!crypto_provider_) {
        crypto_provider_ = std::make_shared<crypto::DefaultCryptoProvider>();
    }
}

Result<Bytes> UavAuthInitiator::initiate(Timestamp now_ms) {
    state_ = HandshakeState::WaitServerHello;

    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    AuthReq req;
    std::copy(our_cert_.subject_node_id().begin(), our_cert_.subject_node_id().end(), req.node_id.begin());
    req.cert = our_cert_;

    // Generate KEM ephemeral keypair
    auto kem = crypto_provider_->create_ml_kem(crypto::MlKem::Level::Kem768);
    auto kem_kp_r = kem->generate_keypair();
    if (!kem_kp_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(kem_kp_r.error());
    }
    kem_kp_ = std::move(kem_kp_r.value());
    req.kem_pub = kem_kp_.public_key.data;

    // Generate nonce
    auto rand_bytes_r = crypto_provider_->generate_random_bytes(16);
    if (!rand_bytes_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(rand_bytes_r.error());
    }
    req.u_nonce = std::move(rand_bytes_r.value());
    sent_nonce_ = req.u_nonce;
    req.timestamp = current_time;

    // Sign request
    auto mldsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
    auto sig_r = mldsa->sign(our_ml_dsa_key_.private_key, req.get_to_be_signed_bytes());
    if (!sig_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(sig_r.error());
    }
    req.signature = std::move(sig_r.value().data);

    Bytes body = req.serialise();
    MessageHeader hdr;
    hdr.type = MessageType::AuthReq;
    hdr.length = static_cast<std::uint16_t>(body.size());

    Bytes pkt = hdr.serialise();
    pkt.insert(pkt.end(), body.begin(), body.end());
    UAV_PQC_LOG_INFO("protocol.auth", "UAV initiated mutual authentication AUTH_REQ");
    return ok<Bytes>(std::move(pkt));
}

Result<Bytes> UavAuthInitiator::handle_challenge(ByteSpan challenge_msg, Timestamp now_ms) {
    if (challenge_msg.size() < MessageHeader::kWireSize) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::InvalidArgument, "Challenge too short");
    }

    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    Timestamp cert_time = now_ms;
    if (cert_time == 0 && clock_) {
        cert_time = clock_->wall_clock_ms();
    }

    auto hdr_r = MessageHeader::deserialise(challenge_msg.subspan(0, MessageHeader::kWireSize));
    if (!hdr_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(hdr_r.error());
    }

    ByteSpan body = challenge_msg.subspan(MessageHeader::kWireSize, hdr_r.value().length);

    if (hdr_r.value().type == MessageType::AuthFail) {
        state_ = HandshakeState::Failed;
        auto fail_r = AuthFail::deserialise(body);
        if (!fail_r) return err<Bytes>(ErrorCode::AuthenticationFailed, "Auth challenge rejected");
        return err<Bytes>(ErrorCode::AuthenticationFailed, "Challenge rejected: " + fail_r.value().description);
    }

    if (hdr_r.value().type != MessageType::AuthChallenge) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::UnsupportedOperation, "Expected AuthChallenge");
    }

    auto ch_r = AuthChallenge::deserialise(body);
    if (!ch_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ch_r.error());
    }

    const auto& ch = ch_r.value();

    // 1. Verify GCS cert chains to CA anchor
    identity::TrustChain trust_chain({ ca_anchor_ }, clock_);
    auto val_r = trust_chain.validate({ ch.cert, ca_anchor_ }, cert_time);
    if (!val_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(val_r.error());
    }

    // 2. Verify GCS signature
    auto mldsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
    crypto::Signature sig;
    sig.data = ch.signature;
    auto verify_r = mldsa->verify(ch.cert.ml_dsa_public_key(), ch.get_to_be_signed_bytes(), sig);
    if (!verify_r.has_value() || !verify_r.value()) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::VerificationFailed, "GCS signature verification failed");
    }

    // 3. Verify echoed nonce
    if (ch.u_nonce != sent_nonce_) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::AuthenticationFailed, "Echoed UAV nonce mismatch");
    }

    // 4. Verify timestamp freshness (±5 mins)
    std::int64_t diff = static_cast<std::int64_t>(ch.timestamp) - static_cast<std::int64_t>(current_time);
    if (std::abs(diff) > 300000) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::AuthenticationFailed, "Timestamp expired");
    }

    received_nonce_ = ch.g_nonce;
    peer_node_id_ = ch.node_id;
    peer_dsa_pub_ = ch.cert.ml_dsa_public_key();
    session_id_ = hdr_r.value().session_id;

    // 5. Generate AuthResponse
    AuthResponse resp;
    resp.u_nonce = sent_nonce_;
    resp.g_nonce = received_nonce_;
    resp.timestamp = current_time;

    auto resp_sig_r = mldsa->sign(our_ml_dsa_key_.private_key, resp.get_to_be_signed_bytes());
    if (!resp_sig_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(resp_sig_r.error());
    }
    resp.signature = std::move(resp_sig_r.value().data);

    Bytes resp_body = resp.serialise();
    MessageHeader resp_hdr;
    resp_hdr.type = MessageType::AuthResponse;
    resp_hdr.length = static_cast<std::uint16_t>(resp_body.size());
    resp_hdr.session_id = session_id_;

    Bytes pkt = resp_hdr.serialise();
    pkt.insert(pkt.end(), resp_body.begin(), resp_body.end());

    state_ = HandshakeState::WaitFinished;
    UAV_PQC_LOG_INFO("protocol.auth", "UAV responded to GCS challenge with AUTH_RESPONSE");
    return ok<Bytes>(std::move(pkt));
}

VoidResult UavAuthInitiator::handle_success(ByteSpan success_msg, Timestamp now_ms) {
    if (success_msg.size() < MessageHeader::kWireSize) {
        state_ = HandshakeState::Failed;
        return err(ErrorCode::InvalidArgument, "Success message too short");
    }

    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    auto hdr_r = MessageHeader::deserialise(success_msg.subspan(0, MessageHeader::kWireSize));
    if (!hdr_r) {
        state_ = HandshakeState::Failed;
        return err(hdr_r.error());
    }

    ByteSpan body = success_msg.subspan(MessageHeader::kWireSize, hdr_r.value().length);

    if (hdr_r.value().type == MessageType::AuthFail) {
        state_ = HandshakeState::Failed;
        return err(ErrorCode::AuthenticationFailed, "Auth responder failed");
    }

    if (hdr_r.value().type != MessageType::AuthSuccess) {
        state_ = HandshakeState::Failed;
        return err(ErrorCode::UnsupportedOperation, "Expected AuthSuccess");
    }

    auto succ_r = AuthSuccess::deserialise(body);
    if (!succ_r) {
        state_ = HandshakeState::Failed;
        return err(succ_r.error());
    }

    const auto& succ = succ_r.value();

    // 1. Verify echoed nonce
    if (succ.g_nonce != received_nonce_) {
        state_ = HandshakeState::Failed;
        return err(ErrorCode::AuthenticationFailed, "Echoed GCS nonce mismatch");
    }

    // 2. Verify timestamp freshness
    std::int64_t diff = static_cast<std::int64_t>(succ.timestamp) - static_cast<std::int64_t>(current_time);
    if (std::abs(diff) > 300000) {
        state_ = HandshakeState::Failed;
        return err(ErrorCode::AuthenticationFailed, "Timestamp expired");
    }

    // 3. Verify signature
    auto mldsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
    crypto::Signature sig;
    sig.data = succ.signature;

    auto verify_r = mldsa->verify(peer_dsa_pub_, succ.get_to_be_signed_bytes(), sig);
    if (!verify_r.has_value() || !verify_r.value()) {
        state_ = HandshakeState::Failed;
        return err(ErrorCode::VerificationFailed, "GCS success signature verification failed");
    }

    // 4. Decapsulate Shared Secret
    auto kem = crypto_provider_->create_ml_kem(crypto::MlKem::Level::Kem768);
    crypto::KemCiphertext ct;
    ct.data = succ.kem_ciphertext;
    auto ss_r = kem->decapsulate(kem_kp_.private_key, ct);
    if (!ss_r) {
        state_ = HandshakeState::Failed;
        return err(ss_r.error());
    }
    shared_secret_ = ss_r.value().data.bytes();

    // 5. Derive keys and build active Session
    crypto::AeadKey send_key, recv_key;
    std::array<std::byte, 4> send_prefix, recv_prefix;
    auto derive_r = derive_session_keys(shared_secret_, HandshakeRole::Initiator, session_id_, peer_node_id_, send_key, recv_key, send_prefix, recv_prefix);
    if (!derive_r) {
        state_ = HandshakeState::Failed;
        return err(derive_r.error());
    }

    Timestamp expiry = current_time + 3600000;
    session::Session sess(
        session_id_,
        peer_node_id_,
        default_cipher_suite(),
        std::move(send_key),
        std::move(recv_key),
        send_prefix,
        recv_prefix,
        expiry
    );

    result_ = AuthResult{
        .session = std::move(sess),
        .peer_node_id = peer_node_id_
    };

    state_ = HandshakeState::Complete;
    UAV_PQC_LOG_INFO("protocol.auth", "UAV mutual authentication completed successfully, secure session created");
    return ok();
}

Result<AuthResult> UavAuthInitiator::result() {
    if (state_ != HandshakeState::Complete || !result_.has_value()) {
        return err<AuthResult>(ErrorCode::UnsupportedOperation, "Authentication not complete");
    }
    // We cannot copy Session because it contains non-copyable SecureBytes send_nonces_
    // So we move it out of result_!
    AuthResult res = std::move(result_.value());
    result_ = std::nullopt;
    return ok<AuthResult>(std::move(res));
}

// ── GcsAuthResponder ──────────────────────────────────────────────────────────

GcsAuthResponder::GcsAuthResponder(
    identity::Certificate our_cert,
    const crypto::DsaKeyPair& our_ml_dsa_key,
    identity::Certificate ca_anchor,
    std::shared_ptr<platform::IClock> clock,
    std::shared_ptr<crypto::ICryptoProvider> provider)
    : our_cert_(std::move(our_cert)),
      our_ml_dsa_key_(clone_keypair(our_ml_dsa_key)),
      ca_anchor_(std::move(ca_anchor)),
      clock_(clock),
      crypto_provider_(std::move(provider)) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    if (!crypto_provider_) {
        crypto_provider_ = std::make_shared<crypto::DefaultCryptoProvider>();
    }
}

Result<Bytes> GcsAuthResponder::handle_req(ByteSpan req_msg, Timestamp now_ms) {
    state_ = HandshakeState::WaitClientAuth;

    if (req_msg.size() < MessageHeader::kWireSize) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::InvalidArgument, "Request too short");
    }

    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    Timestamp cert_time = now_ms;
    if (cert_time == 0 && clock_) {
        cert_time = clock_->wall_clock_ms();
    }

    auto hdr_r = MessageHeader::deserialise(req_msg.subspan(0, MessageHeader::kWireSize));
    if (!hdr_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(hdr_r.error());
    }

    if (hdr_r.value().type != MessageType::AuthReq) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::UnsupportedOperation, "Expected AuthReq");
    }

    ByteSpan body = req_msg.subspan(MessageHeader::kWireSize, hdr_r.value().length);
    auto req_r = AuthReq::deserialise(body);
    if (!req_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(req_r.error());
    }

    const auto& req = req_r.value();

    auto reject_response = [&](AuthRejectReason reason, const std::string& desc) -> Result<Bytes> {
        AuthFail fail;
        fail.nonce = req.u_nonce;
        fail.reason = reason;
        fail.description = desc;
        Bytes fail_body = fail.serialise();
        
        MessageHeader fail_hdr;
        fail_hdr.type = MessageType::AuthFail;
        fail_hdr.length = static_cast<std::uint16_t>(fail_body.size());
        
        Bytes pkt = fail_hdr.serialise();
        pkt.insert(pkt.end(), fail_body.begin(), fail_body.end());
        state_ = HandshakeState::Failed;
        return ok<Bytes>(std::move(pkt));
    };

    // 1. Check timestamp
    std::int64_t diff = static_cast<std::int64_t>(req.timestamp) - static_cast<std::int64_t>(current_time);
    if (std::abs(diff) > 300000) {
        return reject_response(AuthRejectReason::ExpiredTimestamp, "Timestamp expired");
    }

    // 2. Check nonce replay
    if (std::find(seen_nonces_.begin(), seen_nonces_.end(), req.u_nonce) != seen_nonces_.end()) {
        return reject_response(AuthRejectReason::ReplayDetected, "Replayed nonce");
    }
    seen_nonces_.push_back(req.u_nonce);

    // 3. Verify UAV cert chains to CA
    identity::TrustChain trust_chain({ ca_anchor_ }, clock_);
    auto val_r = trust_chain.validate({ req.cert, ca_anchor_ }, cert_time);
    if (!val_r) {
        return reject_response(AuthRejectReason::InvalidCertificate, "UAV cert verification failed");
    }

    // 4. Verify UAV signature
    auto mldsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
    crypto::Signature sig;
    sig.data = req.signature;
    auto verify_r = mldsa->verify(req.cert.ml_dsa_public_key(), req.get_to_be_signed_bytes(), sig);
    if (!verify_r.has_value() || !verify_r.value()) {
        return reject_response(AuthRejectReason::InvalidSignature, "UAV signature verification failed");
    }

    received_nonce_ = req.u_nonce;
    peer_kem_pub_ = req.kem_pub;
    peer_node_id_ = req.node_id;
    peer_dsa_pub_ = req.cert.ml_dsa_public_key();

    // Generate random session ID for header
    auto rand_sid_r = crypto_provider_->generate_random_bytes(16);
    if (!rand_sid_r) {
        return reject_response(AuthRejectReason::Unknown, "Session ID generation failed");
    }
    std::copy(rand_sid_r.value().begin(), rand_sid_r.value().end(), session_id_.begin());

    // 5. Generate AuthChallenge
    AuthChallenge ch;
    std::copy(our_cert_.subject_node_id().begin(), our_cert_.subject_node_id().end(), ch.node_id.begin());
    ch.cert = our_cert_;
    ch.u_nonce = received_nonce_;
    
    auto rand_gn_r = crypto_provider_->generate_random_bytes(16);
    if (!rand_gn_r) {
        return reject_response(AuthRejectReason::Unknown, "Nonce generation failed");
    }
    ch.g_nonce = std::move(rand_gn_r.value());
    sent_nonce_ = ch.g_nonce;
    ch.timestamp = current_time;

    auto ch_sig_r = mldsa->sign(our_ml_dsa_key_.private_key, ch.get_to_be_signed_bytes());
    if (!ch_sig_r) {
        return reject_response(AuthRejectReason::Unknown, "GCS challenge signature generation failed");
    }
    ch.signature = std::move(ch_sig_r.value().data);

    Bytes ch_body = ch.serialise();
    MessageHeader ch_hdr;
    ch_hdr.type = MessageType::AuthChallenge;
    ch_hdr.length = static_cast<std::uint16_t>(ch_body.size());
    ch_hdr.session_id = session_id_;

    Bytes pkt = ch_hdr.serialise();
    pkt.insert(pkt.end(), ch_body.begin(), ch_body.end());

    state_ = HandshakeState::WaitClientAuth;
    UAV_PQC_LOG_INFO("protocol.auth", "GCS processed AUTH_REQ and generated AUTH_CHALLENGE");
    return ok<Bytes>(std::move(pkt));
}

Result<Bytes> GcsAuthResponder::handle_response(ByteSpan response_msg, Timestamp now_ms) {
    if (response_msg.size() < MessageHeader::kWireSize) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::InvalidArgument, "Response message too short");
    }

    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    auto hdr_r = MessageHeader::deserialise(response_msg.subspan(0, MessageHeader::kWireSize));
    if (!hdr_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(hdr_r.error());
    }

    ByteSpan body = response_msg.subspan(MessageHeader::kWireSize, hdr_r.value().length);

    if (hdr_r.value().type != MessageType::AuthResponse) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(ErrorCode::UnsupportedOperation, "Expected AuthResponse");
    }

    auto resp_r = AuthResponse::deserialise(body);
    if (!resp_r) {
        state_ = HandshakeState::Failed;
        return err<Bytes>(resp_r.error());
    }

    const auto& resp = resp_r.value();

    auto reject_response = [&](AuthRejectReason reason, const std::string& desc) -> Result<Bytes> {
        AuthFail fail;
        fail.nonce = resp.g_nonce;
        fail.reason = reason;
        fail.description = desc;
        Bytes fail_body = fail.serialise();
        
        MessageHeader fail_hdr;
        fail_hdr.type = MessageType::AuthFail;
        fail_hdr.length = static_cast<std::uint16_t>(fail_body.size());
        
        Bytes pkt = fail_hdr.serialise();
        pkt.insert(pkt.end(), fail_body.begin(), fail_body.end());
        state_ = HandshakeState::Failed;
        return ok<Bytes>(std::move(pkt));
    };

    // 1. Verify nonces
    if (resp.u_nonce != received_nonce_) {
        return reject_response(AuthRejectReason::ReplayDetected, "UAV nonce mismatch");
    }
    if (resp.g_nonce != sent_nonce_) {
        return reject_response(AuthRejectReason::ReplayDetected, "GCS nonce mismatch");
    }

    // 2. Verify timestamp freshness
    std::int64_t diff = static_cast<std::int64_t>(resp.timestamp) - static_cast<std::int64_t>(current_time);
    if (std::abs(diff) > 300000) {
        return reject_response(AuthRejectReason::ExpiredTimestamp, "Timestamp expired");
    }

    // 3. Verify UAV signature
    auto mldsa = crypto_provider_->create_ml_dsa(crypto::MlDsa::Level::Dsa65);
    crypto::Signature sig;
    sig.data = resp.signature;
    auto verify_r = mldsa->verify(peer_dsa_pub_, resp.get_to_be_signed_bytes(), sig);
    if (!verify_r.has_value() || !verify_r.value()) {
        return reject_response(AuthRejectReason::InvalidSignature, "UAV signature verification failed");
    }

    // 4. Perform KEM Encapsulation using peer's KEM public key
    auto kem = crypto_provider_->create_ml_kem(crypto::MlKem::Level::Kem768);
    crypto::KemPublicKey pk;
    pk.data = peer_kem_pub_;
    auto enc_r = kem->encapsulate(pk);
    if (!enc_r) {
        return reject_response(AuthRejectReason::DecapsulationFailed, "KEM encapsulation failed");
    }
    shared_secret_ = enc_r.value().shared_secret.data.bytes();
    Bytes kem_ciphertext = std::move(enc_r.value().ciphertext.data);

    // 5. Derive keys and build active Session
    crypto::AeadKey send_key, recv_key;
    std::array<std::byte, 4> send_prefix, recv_prefix;
    auto derive_r = derive_session_keys(shared_secret_, HandshakeRole::Responder, session_id_, peer_node_id_, send_key, recv_key, send_prefix, recv_prefix);
    if (!derive_r) {
        return reject_response(AuthRejectReason::Unknown, "Key derivation failed");
    }

    Timestamp expiry = current_time + 3600000;
    session::Session sess(
        session_id_,
        peer_node_id_,
        default_cipher_suite(),
        std::move(send_key),
        std::move(recv_key),
        send_prefix,
        recv_prefix,
        expiry
    );

    result_ = AuthResult{
        .session = std::move(sess),
        .peer_node_id = peer_node_id_
    };

    // 6. Generate and sign AuthSuccess
    AuthSuccess succ;
    succ.g_nonce = sent_nonce_;
    succ.kem_ciphertext = std::move(kem_ciphertext);
    succ.timestamp = current_time;

    auto succ_sig_r = mldsa->sign(our_ml_dsa_key_.private_key, succ.get_to_be_signed_bytes());
    if (!succ_sig_r) {
        return reject_response(AuthRejectReason::Unknown, "GCS success signature generation failed");
    }
    succ.signature = std::move(succ_sig_r.value().data);

    Bytes succ_body = succ.serialise();
    MessageHeader succ_hdr;
    succ_hdr.type = MessageType::AuthSuccess;
    succ_hdr.length = static_cast<std::uint16_t>(succ_body.size());
    succ_hdr.session_id = session_id_;

    Bytes pkt = succ_hdr.serialise();
    pkt.insert(pkt.end(), succ_body.begin(), succ_body.end());

    state_ = HandshakeState::Complete;
    UAV_PQC_LOG_INFO("protocol.auth", "GCS processed AUTH_RESPONSE and generated AUTH_SUCCESS");
    return ok<Bytes>(std::move(pkt));
}

Result<AuthResult> GcsAuthResponder::result() {
    if (state_ != HandshakeState::Complete || !result_.has_value()) {
        return err<AuthResult>(ErrorCode::UnsupportedOperation, "Authentication not complete");
    }
    AuthResult res = std::move(result_.value());
    result_ = std::nullopt;
    return ok<AuthResult>(std::move(res));
}

} // namespace uav_pqc::protocol
