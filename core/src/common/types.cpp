// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file types.cpp
 * @brief Implementations for byte-buffer utility functions declared in types.hpp.
 *
 * All functions are intentionally kept short and pure to allow easy porting
 * to bare-metal targets (STM32, RP2040) where large standard library
 * facilities may not be present.
 */

#include "uav_pqc/common/types.hpp"

#include <cstdio>

namespace uav_pqc {

// ── to_hex ────────────────────────────────────────────────────────────────────

std::string to_hex(ByteSpan data) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (const std::byte b : data) {
        const auto u = static_cast<std::uint8_t>(b);
        result.push_back(kHexDigits[u >> 4u]);
        result.push_back(kHexDigits[u & 0x0Fu]);
    }
    return result;
}

// ── from_hex ──────────────────────────────────────────────────────────────────

Bytes from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) return {};

    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    Bytes result;
    result.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return {}; // malformed
        result.push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return result;
}

// ── constant_time_equal ───────────────────────────────────────────────────────

bool constant_time_equal(ByteSpan a, ByteSpan b) noexcept {
    if (a.size() != b.size()) return false;
    volatile std::uint8_t diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<std::uint8_t>(a[i]) ^
                static_cast<std::uint8_t>(b[i]);
    }
    return diff == 0;
}

// ── secure_zero ───────────────────────────────────────────────────────────────
// NOTE: This function is declared in types.hpp only to be called from
// AEAD implementations on error paths.  It is defined here so it is
// compiled into the common library (not inline) preventing the compiler
// from eliding it even with -O3 -flto.

void secure_zero(MutableByteSpan buf) noexcept {
    volatile std::byte* p = buf.data();
    for (std::size_t i = 0; i < buf.size(); ++i) {
        p[i] = std::byte{0};
    }
}

} // namespace uav_pqc
