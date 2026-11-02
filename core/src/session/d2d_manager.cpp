// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/session/d2d_manager.hpp"
#include "uav_pqc/crypto/aes_gcm.hpp"

#include <cstring>
#include <algorithm>

namespace uav_pqc::session {

Result<SessionId> D2DSessionManager::add_session(D2DSession session) {
    std::lock_guard<std::mutex> lock(mutex_);
    SessionId sid = session.session_id;

    sessions_[sid] = std::move(session);
    stats_.active_sessions = sessions_.size();
    stats_.total_sessions_created++;
    return sid;
}

std::optional<D2DSession> D2DSessionManager::get_session(const SessionId& sid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second.clone();
}

std::optional<D2DSession> D2DSessionManager::find_session_by_peer(const NodeId& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [sid, sess] : sessions_) {
        if (sess.state == D2DSessionState::Active && sess.peer_node_id == peer_id) {
            return sess.clone();
        }
    }
    return std::nullopt;
}

bool D2DSessionManager::terminate_session(const SessionId& sid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sid);
    if (it != sessions_.end()) {
        it->second.session_key.erase();
        sessions_.erase(it);
        stats_.active_sessions = sessions_.size();
        stats_.total_sessions_terminated++;
        return true;
    }
    return false;
}

std::size_t D2DSessionManager::cleanup_expired_sessions(Timestamp current_time) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t pruned = 0;

    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second.is_expired(current_time)) {
            it->second.session_key.erase();
            it = sessions_.erase(it);
            pruned++;
            stats_.total_sessions_expired++;
        } else {
            ++it;
        }
    }
    stats_.active_sessions = sessions_.size();
    return pruned;
}

void D2DSessionManager::clear_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [sid, sess] : sessions_) {
        sess.session_key.erase();
    }
    sessions_.clear();
    stats_.active_sessions = 0;
}

Result<Bytes> D2DSessionManager::encrypt_payload(const SessionId& sid, ByteSpan plaintext, Timestamp now) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) {
        return ErrorCode::SessionNotFound;
    }
    if (it->second.is_expired(now)) {
        it->second.session_key.erase();
        sessions_.erase(it);
        stats_.total_sessions_expired++;
        stats_.active_sessions = sessions_.size();
        return ErrorCode::SessionExpired;
    }

    // Construct 12-byte AEAD Nonce: [4-byte SID prefix][8-byte tx_seq]
    std::array<std::byte, 12> nonce{};
    std::memcpy(nonce.data(), it->second.session_id.data(), 4);
    std::uint64_t seq = it->second.tx_seq++;
    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<std::byte>((seq >> ((7 - i) * 8)) & 0xFF);
    }

    crypto::AeadKey aead_key = crypto::AeadKey::from_bytes(it->second.session_key.span());
    crypto::AesGcm cipher(crypto::AesKeyLen::Aes256);

    // AAD: SessionId (16 bytes)
    ByteSpan aad{it->second.session_id.data(), 16};

    auto enc_res = cipher.encrypt(aead_key, nonce, plaintext, aad);
    if (!enc_res) {
        return enc_res.error();
    }

    // Wire payload layout: [8-byte seq][Encrypted ciphertext + Tag]
    Bytes wire_payload;
    wire_payload.reserve(8 + enc_res.value().size());
    for (int i = 0; i < 8; ++i) {
        wire_payload.push_back(static_cast<std::byte>((seq >> ((7 - i) * 8)) & 0xFF));
    }
    wire_payload.insert(wire_payload.end(), enc_res.value().begin(), enc_res.value().end());

    it->second.touch(now);
    stats_.total_bytes_sent += wire_payload.size();
    stats_.total_packets_sent++;
    return wire_payload;
}

Result<Bytes> D2DSessionManager::decrypt_payload(const SessionId& sid, ByteSpan ciphertext, Timestamp now) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) {
        return ErrorCode::SessionNotFound;
    }
    if (it->second.is_expired(now)) {
        it->second.session_key.erase();
        sessions_.erase(it);
        stats_.total_sessions_expired++;
        stats_.active_sessions = sessions_.size();
        return ErrorCode::SessionExpired;
    }

    if (ciphertext.size() < 8 + 16) { // 8-byte seq + 16-byte GCM tag min
        return ErrorCode::InvalidArgument;
    }

    // Extract 8-byte sequence number
    std::uint64_t seq = 0;
    for (int i = 0; i < 8; ++i) {
        seq = (seq << 8) | static_cast<std::uint64_t>(ciphertext[i]);
    }

    // Replay Protection: require monotonically non-decreasing sequence number
    if (seq < it->second.rx_seq && it->second.rx_seq > 0) {
        return ErrorCode::ReplayDetected;
    }

    // Reconstruct 12-byte AEAD Nonce
    std::array<std::byte, 12> nonce{};
    std::memcpy(nonce.data(), it->second.session_id.data(), 4);
    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<std::byte>((seq >> ((7 - i) * 8)) & 0xFF);
    }

    crypto::AeadKey aead_key = crypto::AeadKey::from_bytes(it->second.session_key.span());
    crypto::AesGcm cipher(crypto::AesKeyLen::Aes256);
    ByteSpan aad{it->second.session_id.data(), 16};

    ByteSpan enc_body = ciphertext.subspan(8);
    auto dec_res = cipher.decrypt(aead_key, nonce, enc_body, aad);
    if (!dec_res) {
        return dec_res.error();
    }

    it->second.rx_seq = seq + 1;
    it->second.touch(now);
    stats_.total_bytes_received += ciphertext.size();
    stats_.total_packets_received++;
    return dec_res.value();
}

D2DStatistics D2DSessionManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

std::size_t D2DSessionManager::get_session_object_size(const D2DSession& session) noexcept {
    return sizeof(D2DSession) + session.peer_ip.capacity() + session.session_key.capacity();
}

std::size_t D2DSessionManager::get_active_session_memory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t mem = sizeof(D2DSessionManager);
    mem += sessions_.bucket_count() * sizeof(void*);
    for (const auto& [id, sess] : sessions_) {
        // Node overhead + element size + dynamic allocations
        mem += sizeof(void*) * 2; // linked list pointers in bucket
        mem += sizeof(SessionId);
        mem += get_session_object_size(sess);
    }
    return mem;
}

} // namespace uav_pqc::session
