// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file random_ns3.cpp
 * @brief Deterministic pseudo-random number generator implementation for ns-3 simulations.
 */

#include "uav_pqc/platform/random.hpp"
#include <ns3/double.h>
#include <ns3/pointer.h>
#include <ns3/random-variable-stream.h>

namespace uav_pqc::platform {

class Ns3Rng final : public ISecureRng {
public:
    Ns3Rng() {
        rng_ = ns3::CreateObject<ns3::UniformRandomVariable>();
        rng_->SetAttribute("Min", ns3::DoubleValue(0.0));
        rng_->SetAttribute("Max", ns3::DoubleValue(256.0));
    }

    [[nodiscard]] VoidResult fill(MutableByteSpan out) noexcept override {
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = static_cast<std::byte>(static_cast<std::uint8_t>(rng_->GetValue()));
        }
        return ok();
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

private:
    ns3::Ptr<ns3::UniformRandomVariable> rng_;
};

std::unique_ptr<ISecureRng> make_platform_rng() {
    return std::make_unique<Ns3Rng>();
}

} // namespace uav_pqc::platform
