// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#include "uav_pqc/protocol/d2d_handshake.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include <cstring>
#include <iostream>
#include <iomanip>

namespace uav_pqc::protocol {

// D2DDirectHelloPayload
Bytes D2DDirectHelloPayload::serialize() const {
    Bytes out;
    out.insert(out.end(), initiator_id.begin(), initiator_id.end());
    out.insert(out.end(), target_id.begin(), target_id.end());
    out.insert(out.end(), nonce.begin(), nonce.end());

    std::uint32_t kem_len = static_cast<std::uint32_t>(kem_public_key.size());
    Bytes kem_len_b(4);
    std::memcpy(kem_len_b.data(), &kem_len, 4);
    out.insert(out.end(), kem_len_b.begin(), kem_len_b.end());
    out.insert(out.end(), kem_public_key.begin(), kem_public_key.end());

    std::uint32_t cert_len = static_cast<std::uint32_t>(initiator_cert.size());
    Bytes cert_len_b(4);
    std::memcpy(cert_len_b.data(), &cert_len, 4);
    out.insert(out.end(), cert_len_b.begin(), cert_len_b.end());
    out.insert(out.end(), initiator_cert.begin(), initiator_cert.end());

    return out;
}

Result<D2DDirectHelloPayload> D2DDirectHelloPayload::deserialize(ByteSpan bytes) {
    if (bytes.size() < 32 + 32 + 16 + 4 + 4) {
        return err<D2DDirectHelloPayload>(ErrorCode::InvalidArgument, "D2DDirectHelloPayload too short");
    }

    D2DDirectHelloPayload p;
    std::size_t offset = 0;

    std::memcpy(p.initiator_id.data(), bytes.data() + offset, 32); offset += 32;
    std::memcpy(p.target_id.data(), bytes.data() + offset, 32); offset += 32;
    std::memcpy(p.nonce.data(), bytes.data() + offset, 16); offset += 16;

    std::uint32_t kem_len = 0;
    std::memcpy(&kem_len, bytes.data() + offset, 4); offset += 4;
    if (bytes.size() < offset + kem_len + 4) {
        return err<D2DDirectHelloPayload>(ErrorCode::InvalidArgument, "D2DDirectHelloPayload invalid kem_len");
    }
    p.kem_public_key.assign(bytes.begin() + offset, bytes.begin() + offset + kem_len);
    offset += kem_len;

    std::uint32_t cert_len = 0;
    std::memcpy(&cert_len, bytes.data() + offset, 4); offset += 4;
    if (bytes.size() < offset + cert_len) {
        return err<D2DDirectHelloPayload>(ErrorCode::InvalidArgument, "D2DDirectHelloPayload invalid cert_len");
    }
    p.initiator_cert.assign(bytes.begin() + offset, bytes.begin() + offset + cert_len);

    return p;
}

// D2DDirectRespPayload
Bytes D2DDirectRespPayload::serialize() const {
    Bytes out;
    out.insert(out.end(), target_id.begin(), target_id.end());
    out.insert(out.end(), initiator_id.begin(), initiator_id.end());
    out.insert(out.end(), session_id.begin(), session_id.end());
    out.insert(out.end(), nonce.begin(), nonce.end());

    std::uint32_t ct_len = static_cast<std::uint32_t>(kem_ciphertext.size());
    Bytes ct_len_b(4);
    std::memcpy(ct_len_b.data(), &ct_len, 4);
    out.insert(out.end(), ct_len_b.begin(), ct_len_b.end());
    out.insert(out.end(), kem_ciphertext.begin(), kem_ciphertext.end());

    std::uint32_t cert_len = static_cast<std::uint32_t>(target_cert.size());
    Bytes cert_len_b(4);
    std::memcpy(cert_len_b.data(), &cert_len, 4);
    out.insert(out.end(), cert_len_b.begin(), cert_len_b.end());
    out.insert(out.end(), target_cert.begin(), target_cert.end());

    std::uint32_t sig_len = static_cast<std::uint32_t>(signature.size());
    Bytes sig_len_b(4);
    std::memcpy(sig_len_b.data(), &sig_len, 4);
    out.insert(out.end(), sig_len_b.begin(), sig_len_b.end());
    out.insert(out.end(), signature.begin(), signature.end());

    return out;
}

Result<D2DDirectRespPayload> D2DDirectRespPayload::deserialize(ByteSpan bytes) {
    if (bytes.size() < 32 + 32 + 16 + 16 + 4 + 4 + 4) {
        return err<D2DDirectRespPayload>(ErrorCode::InvalidArgument, "D2DDirectRespPayload too short");
    }

    D2DDirectRespPayload p;
    std::size_t offset = 0;

    std::memcpy(p.target_id.data(), bytes.data() + offset, 32); offset += 32;
    std::memcpy(p.initiator_id.data(), bytes.data() + offset, 32); offset += 32;
    std::memcpy(p.session_id.data(), bytes.data() + offset, 16); offset += 16;
    std::memcpy(p.nonce.data(), bytes.data() + offset, 16); offset += 16;

    std::uint32_t ct_len = 0;
    std::memcpy(&ct_len, bytes.data() + offset, 4); offset += 4;
    if (bytes.size() < offset + ct_len + 4) {
        return err<D2DDirectRespPayload>(ErrorCode::InvalidArgument, "D2DDirectRespPayload invalid ct_len");
    }
    p.kem_ciphertext.assign(bytes.begin() + offset, bytes.begin() + offset + ct_len);
    offset += ct_len;

    std::uint32_t cert_len = 0;
    std::memcpy(&cert_len, bytes.data() + offset, 4); offset += 4;
    if (bytes.size() < offset + cert_len + 4) {
        return err<D2DDirectRespPayload>(ErrorCode::InvalidArgument, "D2DDirectRespPayload invalid cert_len");
    }
    p.target_cert.assign(bytes.begin() + offset, bytes.begin() + offset + cert_len);
    offset += cert_len;

    std::uint32_t sig_len = 0;
    std::memcpy(&sig_len, bytes.data() + offset, 4); offset += 4;
    if (bytes.size() < offset + sig_len) {
        return err<D2DDirectRespPayload>(ErrorCode::InvalidArgument, "D2DDirectRespPayload invalid sig_len");
    }
    p.signature.assign(bytes.begin() + offset, bytes.begin() + offset + sig_len);

    return p;
}

// D2DHandshakeManager
D2DHandshakeManager::D2DHandshakeManager(
    const NodeId& self_id,
    std::shared_ptr<crypto::IKem> kem_engine,
    std::shared_ptr<crypto::IDsa> dsa_engine,
    Bytes self_cert
) : self_id_(self_id), kem_engine_(kem_engine), dsa_engine_(dsa_engine), self_cert_(std::move(self_cert)) {}

Result<D2DDirectHelloPayload> D2DHandshakeManager::initiate_handshake(const NodeId& target_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto kp_r = kem_engine_->generate_keypair();
    if (!kp_r) return err<D2DDirectHelloPayload>(kp_r.error().code, kp_r.error().message);

    crypto::KemKeyPair kp = std::move(kp_r.value());

    D2DDirectHelloPayload hello;
    hello.initiator_id = self_id_;
    hello.target_id = target_id;
    hello.kem_public_key = kp.public_key.data;
    hello.initiator_cert = self_cert_;

    PendingState state;
    state.target_id = target_id;
    state.kem_keypair = std::move(kp);
    pending_handshakes_.insert_or_assign(target_id, std::move(state));

    return hello;
}

Result<std::pair<D2DDirectRespPayload, session::D2DSession>> D2DHandshakeManager::process_hello(
    const D2DDirectHelloPayload& hello,
    Timestamp now_ms
) {
    std::lock_guard<std::mutex> lock(mutex_);

    crypto::KemPublicKey pk{hello.kem_public_key};
    auto enc_r = kem_engine_->encapsulate(pk);
    if (!enc_r) return err<std::pair<D2DDirectRespPayload, session::D2DSession>>(enc_r.error().code, enc_r.error().message);

    crypto::EncapsulationResult enc = std::move(enc_r.value());

    // Derive session key via HKDF-SHA256
    crypto::Hkdf hkdf;
    auto key_r = hkdf.derive(ByteSpan{}, enc.shared_secret.span(), ByteSpan{}, 32);
    if (!key_r) return err<std::pair<D2DDirectRespPayload, session::D2DSession>>(key_r.error().code, key_r.error().message);

    SessionId sid{};
    ByteSpan ss_span = enc.shared_secret.span();
    for (std::size_t i = 0; i < 16; ++i) sid[i] = ss_span[i % ss_span.size()];

    session::D2DSession sess;
    sess.session_id = sid;
    sess.local_node_id = self_id_;
    sess.peer_node_id = hello.initiator_id;
    sess.session_key = SecureBytes(std::move(key_r.value()));
    sess.state = session::D2DSessionState::Active;
    sess.created_at = now_ms;
    sess.last_active_at = now_ms;
    sess.expires_at = now_ms + 300000; // 5 min lifetime

    D2DDirectRespPayload resp;
    resp.target_id = self_id_;
    resp.initiator_id = hello.initiator_id;
    resp.session_id = sid;
    resp.kem_ciphertext = enc.ciphertext.data;
    resp.target_cert = self_cert_;

    return std::make_pair(std::move(resp), std::move(sess));
}

Result<session::D2DSession> D2DHandshakeManager::process_resp(
    const D2DDirectRespPayload& resp,
    Timestamp now_ms
) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = pending_handshakes_.find(resp.target_id);
    if (it == pending_handshakes_.end()) {
        return err<session::D2DSession>(ErrorCode::SessionNotFound, "No pending D2D handshake for target");
    }

    crypto::KemCiphertext ct{resp.kem_ciphertext};
    auto dec_r = kem_engine_->decapsulate(it->second.kem_keypair.private_key, ct);
    if (!dec_r) return err<session::D2DSession>(dec_r.error().code, dec_r.error().message);

    crypto::SharedSecret shared_secret = std::move(dec_r.value());
    crypto::Hkdf hkdf;
    auto key_r = hkdf.derive(ByteSpan{}, shared_secret.span(), ByteSpan{}, 32);
    if (!key_r) return err<session::D2DSession>(key_r.error().code, key_r.error().message);

    session::D2DSession sess;
    sess.session_id = resp.session_id;
    sess.local_node_id = self_id_;
    sess.peer_node_id = resp.target_id;
    sess.session_key = SecureBytes(std::move(key_r.value()));
    sess.state = session::D2DSessionState::Active;
    sess.created_at = now_ms;
    sess.last_active_at = now_ms;
    sess.expires_at = now_ms + 300000; // 5 min lifetime

    pending_handshakes_.erase(it);
    return std::move(sess);
}

} // namespace uav_pqc::protocol
