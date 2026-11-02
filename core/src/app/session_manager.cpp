// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/session_manager.hpp"
#include "uav_pqc/crypto/default_provider.hpp"

namespace uav_pqc::app {

SessionManager::SessionManager(std::shared_ptr<platform::IClock> clock, std::size_t cache_capacity, Timestamp session_ttl_ms, std::shared_ptr<crypto::ICryptoProvider> crypto_provider)
    : cache_(cache_capacity, session_ttl_ms, clock), clock_(clock), crypto_provider_(crypto_provider) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    if (!crypto_provider_) {
        crypto_provider_ = std::make_shared<crypto::DefaultCryptoProvider>();
    }
}

VoidResult SessionManager::add_session(session::Session session, Timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    SessionId id = session.id();
    active_sessions_.insert_or_assign(id, std::move(session));
    return ok();
}

Result<session::Session*> SessionManager::get_session(const SessionId& id, const NodeId& peer, Timestamp now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);

    Timestamp current_time = now_ms;
    if (current_time == 0 && clock_) {
        current_time = clock_->now_ms();
    }

    auto it = active_sessions_.find(id);
    if (it != active_sessions_.end()) {
        if (!it->second.is_valid(current_time)) {
            active_sessions_.erase(it);
            return err<session::Session*>(ErrorCode::SessionExpired, "Session expired/invalid");
        }
        return ok<session::Session*>(&(it->second));
    }

    // Try retrieve from resumption cache
    auto ret_r = cache_.retrieve(id, peer, current_time);
    if (ret_r) {
        auto [inserted_it, inserted] = active_sessions_.insert_or_assign(id, std::move(ret_r.value()));
        return ok<session::Session*>(&(inserted_it->second));
    }

    return err<session::Session*>(ErrorCode::SessionNotFound, "Session not found");
}

void SessionManager::set_group_key(group::GroupKey group_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    group_key_ = std::move(group_key);
}

const group::GroupKey* SessionManager::get_group_key() const noexcept {
    return group_key_ ? &(*group_key_) : nullptr;
}

Result<Bytes> SessionManager::encrypt_group_broadcast(ByteSpan plaintext, ByteSpan aad, std::uint64_t counter) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!group_key_) {
        return err<Bytes>(ErrorCode::SessionNotFound, "No active group key set");
    }
    return group_key_->encrypt(plaintext, aad, counter, crypto_provider_.get());
}

Result<Bytes> SessionManager::decrypt_group_broadcast(ByteSpan ciphertext, ByteSpan aad, std::uint64_t counter) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!group_key_) {
        return err<Bytes>(ErrorCode::SessionNotFound, "No active group key set");
    }
    return group_key_->decrypt(ciphertext, aad, counter, crypto_provider_.get());
}

void SessionManager::clear_sessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    active_sessions_.clear();
    group_key_.reset();
}

} // namespace uav_pqc::app
