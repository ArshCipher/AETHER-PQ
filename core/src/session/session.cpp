// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file session.cpp
 * @brief Active session encrypt/decrypt routing and key rotation.
 */

#include "uav_pqc/session/session.hpp"
#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/crypto/chacha20_poly1305.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/crypto/default_provider.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"
#include "uav_pqc/platform/clock.hpp"
#include <iostream>

namespace uav_pqc::session {

// ── Constructor ───────────────────────────────────────────────────────────────

Session::Session(SessionId                   id,
                 NodeId                      peer_node_id,
                 protocol::CipherSuite       suite,
                 crypto::AeadKey             send_key,
                 crypto::AeadKey             recv_key,
                 std::array<std::byte, 4>    send_prefix,
                 std::array<std::byte, 4>    recv_prefix,
                 Timestamp                   expiry_ms,
                 std::shared_ptr<crypto::ICryptoProvider> crypto_provider)
    : id_(id),
      peer_node_id_(peer_node_id),
      suite_(std::move(suite)),
      send_key_(std::move(send_key)),
      recv_key_(std::move(recv_key)),
      send_nonces_(send_prefix, suite_.max_messages_per_key),
      recv_nonces_(recv_prefix, suite_.max_messages_per_key),
      expiry_ms_(expiry_ms),
      crypto_provider_(crypto_provider) {
    if (!crypto_provider_) {
        crypto_provider_ = std::make_shared<crypto::DefaultCryptoProvider>();
    }
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::SessionCreation);

    // Construct the AEAD engine based on the negotiated suite
    using AeadAlg = protocol::AeadAlgorithm;
    switch (suite_.aead_algorithm) {
        case AeadAlg::AesGcm256:
            aead_ = crypto_provider_->create_aes_gcm(crypto::AesKeyLen::Aes256);
            break;
        case AeadAlg::AesGcm128:
            aead_ = crypto_provider_->create_aes_gcm(crypto::AesKeyLen::Aes128);
            break;
        case AeadAlg::ChaCha20Poly:
            aead_ = crypto_provider_->create_chacha20_poly1305();
            break;
    }

    UAV_PQC_LOG_DEBUG("session", "Session {} created peer={} aead={}",
                      to_hex(ByteSpan{id_.data(), id_.size()}),
                      to_hex(ByteSpan{peer_node_id_.data(), peer_node_id_.size()}),
                      aead_->algorithm_id());
}

// ── encrypt ───────────────────────────────────────────────────────────────────

Result<Bytes> Session::encrypt(ByteSpan plaintext, ByteSpan aad) {
    auto nonce_r = send_nonces_.next_nonce();
    if (!nonce_r) return err<Bytes>(nonce_r.error());

    const auto& nonce = nonce_r.value();
    auto ct_r = aead_->encrypt(send_key_,
        ByteSpan{nonce.data(), nonce.size()}, plaintext, aad);
    if (!ct_r) return err<Bytes>(ct_r.error());

    // Wire = nonce (12 bytes) || ciphertext || tag
    Bytes wire;
    wire.reserve(nonce.size() + ct_r.value().size());
    wire.insert(wire.end(), nonce.begin(), nonce.end());
    wire.insert(wire.end(), ct_r.value().begin(), ct_r.value().end());

    ++stats_.messages_sent;
    stats_.bytes_encrypted += plaintext.size();
    return ok<Bytes>(std::move(wire));
}

Result<Bytes> Session::decrypt(ByteSpan wire_message, ByteSpan aad) {
    constexpr std::size_t kNonceSize = NonceManager::kNonceSize;
    if (wire_message.size() < kNonceSize) {
        return err<Bytes>(ErrorCode::InvalidArgument,
            "Session::decrypt: message too short to contain nonce");
    }

    // Extract nonce
    std::array<std::byte, kNonceSize> nonce{};
    std::copy(wire_message.begin(), wire_message.begin() + kNonceSize, nonce.begin());

    // Anti-replay check
    if (!recv_nonces_.verify_and_advance(nonce)) {
        ++stats_.replay_rejections;
        return err<Bytes>(ErrorCode::ReplayDetected,
            "Session::decrypt: nonce replay or out-of-window");
    }

    const ByteSpan ciphertext_view = wire_message.subspan(kNonceSize);
    auto pt_r = aead_->decrypt(recv_key_,
        ByteSpan{nonce.data(), kNonceSize}, ciphertext_view, aad);
    if (!pt_r) return err<Bytes>(pt_r.error());

    ++stats_.messages_received;
    stats_.bytes_decrypted += pt_r.value().size();
    return pt_r;
}

// ── is_valid ──────────────────────────────────────────────────────────────────

bool Session::is_valid(Timestamp now_ms) const noexcept {
    Timestamp current_time = now_ms;
    if (current_time == 0) {
        auto clk = platform::make_platform_clock();
        current_time = clk->now_ms();
    }
    return current_time < expiry_ms_ && !send_nonces_.is_exhausted();
}

// ── rotate_keys ───────────────────────────────────────────────────────────────

VoidResult Session::rotate_keys() {
    // Derive new send key: HKDF-SHA256(ikm=current_send_key, info="rekey send v1", len=32)
    const auto send_info = bytes_from_sv("uav_pqc session rekey send v1");
    auto new_send_r = crypto_provider_->hkdf_derive(
        suite_.hkdf_hash,
        ByteSpan{},
        send_key_.data.span(),
        ByteSpan{send_info.data(), send_info.size()},
        send_key_.data.size());
    if (!new_send_r) return err(new_send_r.error());

    const auto recv_info = bytes_from_sv("uav_pqc session rekey recv v1");
    auto new_recv_r = crypto_provider_->hkdf_derive(
        suite_.hkdf_hash,
        ByteSpan{},
        recv_key_.data.span(),
        ByteSpan{recv_info.data(), recv_info.size()},
        recv_key_.data.size());
    if (!new_recv_r) return err(new_recv_r.error());

    send_key_ = crypto::AeadKey::from_bytes(new_send_r.value().span());
    recv_key_ = crypto::AeadKey::from_bytes(new_recv_r.value().span());

    // Reset nonce counters
    std::array<std::byte, 4> dummy_prefix{};
    send_nonces_ = NonceManager(dummy_prefix, suite_.max_messages_per_key);
    recv_nonces_ = NonceManager(dummy_prefix, suite_.max_messages_per_key);

    ++stats_.rekey_count;
    UAV_PQC_LOG_INFO("session", "Session {} rotated keys (rekey #{})",
                     to_hex(ByteSpan{id_.data(), id_.size()}), stats_.rekey_count);
    return ok();
}

} // namespace uav_pqc::session
