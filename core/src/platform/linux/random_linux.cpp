// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file random_linux.cpp
 * @brief Secure random number generator implementation using getrandom (Linux) or arc4random_buf (macOS).
 */

#include "uav_pqc/platform/random.hpp"
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

#if defined(__APPLE__)
#include <stdlib.h>
#else
#include <sys/random.h>
#endif

namespace uav_pqc::platform {

class LinuxRng final : public ISecureRng {
public:
    [[nodiscard]] VoidResult fill(MutableByteSpan out) noexcept override {
        if (out.empty()) return ok();

#if defined(__APPLE__)
        ::arc4random_buf(out.data(), out.size());
        return ok();
#else
        std::size_t remaining = out.size();
        std::byte*  ptr       = out.data();
        while (remaining > 0) {
            const ssize_t rc = ::getrandom(ptr, remaining, 0);
            if (rc < 0) {
                if (errno == EINTR) continue;
                return err(ErrorCode::InternalError,
                    std::string("getrandom failed: ") + std::strerror(errno));
            }
            ptr       += static_cast<std::size_t>(rc);
            remaining -= static_cast<std::size_t>(rc);
        }
        return ok();
#endif
    }

    [[nodiscard]] Result<Bytes> generate(std::size_t size) override {
        Bytes buf(size);
        auto r = fill(MutableByteSpan{buf.data(), buf.size()});
        if (!r) return err<Bytes>(r.error());
        return ok<Bytes>(std::move(buf));
    }

    [[nodiscard]] Result<std::uint64_t> generate_u64() override {
        std::uint64_t val = 0;
        MutableByteSpan span{reinterpret_cast<std::byte*>(&val), sizeof(val)};
        auto r = fill(span);
        if (!r) return err<std::uint64_t>(r.error());
        return ok<std::uint64_t>(val);
    }
};

std::unique_ptr<ISecureRng> make_platform_rng() {
    return std::make_unique<LinuxRng>();
}

} // namespace uav_pqc::platform
