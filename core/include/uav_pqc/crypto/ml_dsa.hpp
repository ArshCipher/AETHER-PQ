// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file ml_dsa.hpp
 * @brief ML-DSA (FIPS 204) implementation via liboqs.
 *
 * Supports all three parameter sets:
 *   Level::Dsa44 — ML-DSA-44 (NIST security category 2, Lightweight profile)
 *   Level::Dsa65 — ML-DSA-65 (NIST security category 3, Standard profile)
 *   Level::Dsa87 — ML-DSA-87 (NIST security category 5, Hardened profile)
 *
 * Key / signature sizes (public / private / max-signature):
 *   ML-DSA-44 : 1312 / 2560 / 2420 bytes
 *   ML-DSA-65 : 1952 / 4032 / 3309 bytes
 *   ML-DSA-87 : 2592 / 4896 / 4627 bytes
 *
 * Thread safety: ML-DSA operations are stateless in liboqs; concurrent use
 * of the same MlDsa instance from multiple threads is safe.
 */

#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <memory>
#include <string_view>

struct OQS_SIG;

namespace uav_pqc::crypto {

/**
 * @brief ML-DSA implementation wrapping liboqs OQS_SIG.
 */
class MlDsa final : public IDsa {
public:
    /// ML-DSA parameter set selection.
    enum class Level {
        Dsa44, ///< ML-DSA-44 — Lightweight profile
        Dsa65, ///< ML-DSA-65 — Standard profile (default)
        Dsa87, ///< ML-DSA-87 — Hardened profile
    };

    /**
     * @brief Construct an ML-DSA instance for the given security level.
     * @param level  Parameter set.  Default: Dsa65.
     * @throws std::runtime_error if liboqs cannot load the algorithm.
     */
    explicit MlDsa(Level level = Level::Dsa65);
    ~MlDsa() override;

    MlDsa(const MlDsa&)            = delete;
    MlDsa& operator=(const MlDsa&) = delete;
    MlDsa(MlDsa&&) noexcept;
    MlDsa& operator=(MlDsa&&) noexcept;

    // ── IDsa implementation ───────────────────────────────────────────────────

    [[nodiscard]] Result<DsaKeyPair> generate_keypair()                                   const override;
    [[nodiscard]] Result<Signature>  sign(const DsaPrivateKey& sk, ByteSpan msg)          const override;
    [[nodiscard]] Result<bool>       verify(const DsaPublicKey& pk, ByteSpan msg,
                                            const Signature& sig)                          const override;

    [[nodiscard]] std::string_view algorithm_id()       const noexcept override;
    [[nodiscard]] std::size_t      public_key_size()    const noexcept override;
    [[nodiscard]] std::size_t      private_key_size()   const noexcept override;
    [[nodiscard]] std::size_t      max_signature_size() const noexcept override;

    // ── MlDsa-specific ────────────────────────────────────────────────────────

    [[nodiscard]] Level level() const noexcept { return level_; }
    [[nodiscard]] static std::string_view oqs_method_name(Level level) noexcept;

private:
    Level level_;

    struct OqsSigDeleter {
        void operator()(OQS_SIG* p) const noexcept;
    };
    std::unique_ptr<OQS_SIG, OqsSigDeleter> sig_;
};

} // namespace uav_pqc::crypto
