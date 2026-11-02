// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file nonce_manager.hpp
 * @brief Per-session nonce and sequence counter management.
 *
 * Nonce uniqueness is the critical invariant for AEAD security.  This class
 * owns the per-session nonce counter and enforces:
 *  - Monotonic incrementing (no reuse)
 *  - Nonce exhaustion detection (triggers ErrorCode::NonceExhausted)
 *  - Counter serialisation into the 12-byte nonce format used by both
 *    AES-GCM and ChaCha20-Poly1305
 *
 * Nonce format (96 bits):
 *   [0..3]  : fixed 32-bit session-specific prefix  (prevents cross-session collisions)
 *   [4..11] : 64-bit big-endian monotonic counter
 *
 * The nonce space is 2^64 per session.  The cipher suite max_messages_per_key
 * field limits message count well below 2^64 to trigger rekeying before
 * exhaustion is possible.
 *
 * Thread safety: NonceManager is NOT thread-safe.  Concurrent senders must
 * use an external mutex or each use a distinct NonceManager instance.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cstdint>

namespace uav_pqc::types { class Session; }

namespace uav_pqc::session {

/**
 * @brief Per-direction nonce manager for AEAD operations.
 *
 * Create one instance per send direction per session.  Each call to
 * next_nonce() advances the counter exactly once.
 */
class NonceManager {
public:
    /// Nonce byte length (matches AES-GCM and ChaCha20-Poly1305).
    static constexpr std::size_t kNonceSize = 12;

    /**
     * @brief Construct a NonceManager with a 4-byte session prefix.
     *
     * The prefix is derived from the session key material so it differs
     * across sessions using the same key (defense-in-depth).
     *
     * @param prefix         4-byte session-specific prefix.
     * @param max_messages   Maximum messages before NonceExhausted is returned.
     *                       Default matches Lightweight profile limit.
     * @param initial_counter Starting counter value (0 for new sessions;
     *                        may be non-zero for resumed sessions).
     */
    NonceManager(std::array<std::byte, 4> prefix,
                 std::uint64_t            max_messages    = (1ULL << 32),
                 std::uint64_t            initial_counter = 0);

    ~NonceManager() = default;

    NonceManager(const NonceManager&)            = delete;
    NonceManager& operator=(const NonceManager&) = delete;
    NonceManager(NonceManager&&) noexcept        = default;
    NonceManager& operator=(NonceManager&&) noexcept = default;

    // ── Nonce generation ──────────────────────────────────────────────────────

    /**
     * @brief Generate the next unique nonce.
     *
     * Atomically increments the counter and serialises the result.
     *
     * @return 12-byte nonce, or ErrorCode::NonceExhausted when the counter
     *         reaches max_messages.
     */
    [[nodiscard]] Result<std::array<std::byte, 12>> next_nonce();

    // ── Verification ──────────────────────────────────────────────────────────

    /**
     * @brief Verify that a received nonce is within the acceptable replay window.
     *
     * Uses a 64-bit sliding window to reject replayed or reordered messages.
     * Returns true if the nonce is fresh, false if it has been seen before or
     * lies outside the window.
     *
     * @param received_nonce  12-byte nonce from the received message.
     * @param window_size     Number of messages in the anti-replay window.
     */
    [[nodiscard]] bool verify_and_advance(
        const std::array<std::byte, 12>& received_nonce,
        std::uint64_t                    window_size = 64) noexcept;

    // ── State accessors ───────────────────────────────────────────────────────

    [[nodiscard]] std::uint64_t current_counter()  const noexcept { return counter_; }
    [[nodiscard]] std::uint64_t messages_remaining() const noexcept;
    [[nodiscard]] bool          is_exhausted()      const noexcept;

private:
    friend class ::uav_pqc::types::Session;

    std::array<std::byte, 4> prefix_;
    std::uint64_t            counter_;
    std::uint64_t            max_messages_;
    std::uint64_t            last_received_counter_ = 0;
    std::uint64_t            window_bitmap_          = 0; ///< 64-bit sliding window
};

} // namespace uav_pqc::session
