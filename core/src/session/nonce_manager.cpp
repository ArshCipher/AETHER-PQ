// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file nonce_manager.cpp
 * @brief Per-session nonce counter management and anti-replay window.
 */

#include "uav_pqc/session/nonce_manager.hpp"
#include "uav_pqc/common/logging.hpp"

#include <algorithm>
#include <cstring>

namespace uav_pqc::session {

// ── Constructor ───────────────────────────────────────────────────────────────

NonceManager::NonceManager(std::array<std::byte, 4> prefix,
                            std::uint64_t max_messages,
                            std::uint64_t initial_counter)
    : prefix_(prefix),
      counter_(initial_counter),
      max_messages_(max_messages),
      last_received_counter_(0),
      window_bitmap_(0) {}

// ── next_nonce ────────────────────────────────────────────────────────────────

Result<std::array<std::byte, 12>> NonceManager::next_nonce() {
    if (counter_ >= max_messages_) {
        UAV_PQC_LOG_WARN("session.nonce", "Nonce counter exhausted at {}; rekey required",
                         counter_);
        return err<std::array<std::byte, 12>>(ErrorCode::NonceExhausted,
            "Nonce counter exhausted; session must be rekeyed");
    }

    std::array<std::byte, 12> nonce{};

    // [0..3] = fixed session prefix
    nonce[0] = prefix_[0];
    nonce[1] = prefix_[1];
    nonce[2] = prefix_[2];
    nonce[3] = prefix_[3];

    // [4..11] = 64-bit big-endian counter
    const std::uint64_t c = counter_++;
    for (int i = 7; i >= 0; --i) {
        nonce[static_cast<std::size_t>(4 + i)] = static_cast<std::byte>(c >> (8 * (7 - i)));
    }

    return ok(nonce);
}

// ── verify_and_advance ────────────────────────────────────────────────────────

bool NonceManager::verify_and_advance(const std::array<std::byte, 12>& received_nonce,
                                       std::uint64_t window_size) noexcept {
    // Extract counter from [4..11] big-endian
    std::uint64_t recv_counter = 0;
    for (int i = 0; i < 8; ++i) {
        recv_counter = (recv_counter << 8) |
            static_cast<std::uint8_t>(received_nonce[static_cast<std::size_t>(4 + i)]);
    }

    if (recv_counter > last_received_counter_) {
        // Advance the window
        const std::uint64_t shift = recv_counter - last_received_counter_;
        if (shift >= 64) {
            window_bitmap_ = 0;
        } else {
            window_bitmap_ <<= shift;
        }
        last_received_counter_ = recv_counter;
        window_bitmap_ |= 1ULL; // mark current as received
        return true;
    }

    // Message is within or before the window
    const std::uint64_t age = last_received_counter_ - recv_counter;
    if (age >= window_size) {
        UAV_PQC_LOG_WARN("session.nonce", "Replay detected: counter {} too old (window={})",
                         recv_counter, window_size);
        return false; // outside window → reject
    }

    // Check if this specific bit is already set (replay)
    if ((window_bitmap_ >> age) & 1ULL) {
        UAV_PQC_LOG_WARN("session.nonce", "Replay detected: counter {} already seen",
                         recv_counter);
        return false;
    }

    // Fresh within window; mark it
    window_bitmap_ |= (1ULL << age);
    return true;
}

// ── State accessors ───────────────────────────────────────────────────────────

std::uint64_t NonceManager::messages_remaining() const noexcept {
    return (counter_ < max_messages_) ? (max_messages_ - counter_) : 0;
}

bool NonceManager::is_exhausted() const noexcept {
    return counter_ >= max_messages_;
}

} // namespace uav_pqc::session
