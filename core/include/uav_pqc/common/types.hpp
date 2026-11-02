// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file types.hpp
 * @brief Fundamental types used throughout the uav_pqc library.
 *
 * All primitive typedef/using declarations live here to give a single
 * authoritative place for the core byte-buffer and ID types.  Keeping types
 * here avoids circular includes and makes the codebase STM32-portable (no
 * POSIX headers required in this file).
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#if __has_include(<span>)
#include <span>
#endif

namespace uav_pqc {

// ─────────────────────────────────────────────────────────────────────────────
// Byte-buffer types
// ─────────────────────────────────────────────────────────────────────────────

/// Owning dynamic byte buffer.
using Bytes = std::vector<std::byte>;

#if defined(__cpp_lib_span) || (defined(__cplusplus) && __cplusplus >= 202002L)
/// Non-owning, read-only view of a contiguous byte sequence.
using ByteSpan = std::span<const std::byte>;

/// Non-owning, read-write view of a contiguous byte sequence.
using MutableByteSpan = std::span<std::byte>;
#else
namespace custom {
template<typename T>
class span {
private:
    T* data_ = nullptr;
    size_t size_ = 0;
public:
    constexpr span() noexcept = default;
    constexpr span(T* ptr, size_t count) noexcept : data_(ptr), size_(count) {}
    
    template<typename U, size_t N>
    constexpr span(std::array<U, N>& arr) noexcept : data_(reinterpret_cast<T*>(arr.data())), size_(N) {}
    
    template<typename U, size_t N>
    constexpr span(const std::array<U, N>& arr) noexcept : data_(reinterpret_cast<T*>(arr.data())), size_(N) {}

    template<typename U>
    constexpr span(std::vector<U>& vec) noexcept : data_(reinterpret_cast<T*>(vec.data())), size_(vec.size()) {}

    template<typename U>
    constexpr span(const std::vector<U>& vec) noexcept : data_(reinterpret_cast<T*>(vec.data())), size_(vec.size()) {}

    constexpr T* data() const noexcept { return data_; }
    constexpr size_t size() const noexcept { return size_; }
    constexpr bool empty() const noexcept { return size_ == 0; }
    constexpr T* begin() const noexcept { return data_; }
    constexpr T* end() const noexcept { return data_ + size_; }
    constexpr T& operator[](size_t idx) const noexcept { return data_[idx]; }
    constexpr span<T> subspan(size_t offset, size_t count = static_cast<size_t>(-1)) const noexcept {
        size_t actual_count = (count == static_cast<size_t>(-1)) ? (size_ - offset) : count;
        return {data_ + offset, actual_count};
    }
};
} // namespace custom

using ByteSpan = custom::span<const std::byte>;
using MutableByteSpan = custom::span<std::byte>;
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Identity and session primitives
// ─────────────────────────────────────────────────────────────────────────────

/// 256-bit node identifier (SHA-256 of the long-term public key).
using NodeId = std::array<std::byte, 32>;

/// 128-bit session identifier (cryptographically random).
using SessionId = std::array<std::byte, 16>;

/// 64-bit monotonically increasing group key epoch counter.
using GroupEpoch = std::uint64_t;

/// 64-bit per-session sequence/nonce counter (anti-replay).
using SequenceNumber = std::uint64_t;

/// Milliseconds since Unix epoch (uint64_t avoids signed-overflow on embedded).
using Timestamp = std::uint64_t;

// ─────────────────────────────────────────────────────────────────────────────
// Fixed-size nonce types
// ─────────────────────────────────────────────────────────────────────────────

/// Generic N-byte nonce.
template <std::size_t N>
using Nonce = std::array<std::byte, N>;

/// 96-bit (12-byte) AES-GCM nonce.
using AesGcmNonce = Nonce<12>;

/// 96-bit (12-byte) ChaCha20-Poly1305 nonce.
using ChaCha20Nonce = Nonce<12>;

// ─────────────────────────────────────────────────────────────────────────────
// SecureBytes — RAII wrapper that zeroes memory on destruction
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Owning byte buffer that performs a volatile-write memory erase on
 *        destruction.  Used for private keys and shared secrets.
 *
 * Movable but not copyable to prevent accidental duplication of secrets.
 */
class SecureBytes {
public:
    SecureBytes() = default;

    explicit SecureBytes(std::size_t size) : data_(size, std::byte{0}) {}

    explicit SecureBytes(Bytes&& src) noexcept : data_(std::move(src)) {}

    SecureBytes(const SecureBytes&)            = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    SecureBytes(SecureBytes&&) noexcept            = default;
    SecureBytes& operator=(SecureBytes&&) noexcept = default;

    ~SecureBytes() { erase(); }

    [[nodiscard]] SecureBytes clone() const {
        SecureBytes copy(data_.size());
        std::copy(data_.begin(), data_.end(), copy.data());
        return copy;
    }

    [[nodiscard]] std::byte*       data() noexcept { return data_.data(); }
    [[nodiscard]] const std::byte* data() const noexcept { return data_.data(); }
    [[nodiscard]] std::size_t      size() const noexcept { return data_.size(); }
    [[nodiscard]] bool             empty() const noexcept { return data_.empty(); }
    [[nodiscard]] std::size_t      capacity() const noexcept { return data_.capacity(); }

    [[nodiscard]] MutableByteSpan span() noexcept { return {data_.data(), data_.size()}; }
    [[nodiscard]] ByteSpan        span() const noexcept { return {data_.data(), data_.size()}; }

    /// Access underlying storage (read-only).
    [[nodiscard]] const Bytes& bytes() const noexcept { return data_; }

    void resize(std::size_t n) { data_.resize(n, std::byte{0}); }

    void erase() noexcept {
        volatile std::byte* p = data_.data();
        for (std::size_t i = 0; i < data_.size(); ++i) {
            p[i] = std::byte{0};
        }
    }

private:
    Bytes data_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Utility free functions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Encode a byte span as a lowercase hexadecimal string.
 * @param data  Input byte sequence.
 * @return      Hex string of length 2 × data.size().
 */
[[nodiscard]] std::string to_hex(ByteSpan data);

/**
 * @brief Decode a hexadecimal string into a Bytes buffer.
 * @param hex   Even-length hex string.
 * @return      Decoded bytes, or an empty Bytes if input is malformed.
 */
[[nodiscard]] Bytes from_hex(std::string_view hex);

/**
 * @brief Create a Bytes buffer from a string_view (byte-for-byte copy).
 */
[[nodiscard]] inline Bytes bytes_from_sv(std::string_view sv) {
    Bytes result(sv.size());
    std::transform(sv.begin(), sv.end(), result.begin(),
                   [](char c) { return static_cast<std::byte>(c); });
    return result;
}

/**
 * @brief Write a 64-bit unsigned integer in big-endian byte order into dst.
 * @param dst  Must have at least 8 bytes available.
 * @param val  Value to encode.
 */
inline void write_u64_be(MutableByteSpan dst, std::uint64_t val) noexcept {
    for (int i = 7; i >= 0; --i) {
        dst[static_cast<std::size_t>(i)] = static_cast<std::byte>(val & 0xFFu);
        val >>= 8u;
    }
}

/**
 * @brief Read a 64-bit unsigned integer in big-endian byte order from src.
 * @param src  Must have at least 8 bytes.
 */
[[nodiscard]] inline std::uint64_t read_u64_be(ByteSpan src) noexcept {
    std::uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8u) | static_cast<std::uint8_t>(src[static_cast<std::size_t>(i)]);
    }
    return val;
}

/**
 * @brief Constant-time comparison of two byte sequences.
 * @return true  if both spans are equal in length and content.
 */
[[nodiscard]] bool constant_time_equal(ByteSpan a, ByteSpan b) noexcept;

/**
 * @brief Zero a memory buffer in a way that the compiler cannot optimise away.
 */
void secure_zero(MutableByteSpan buf) noexcept;

} // namespace uav_pqc
