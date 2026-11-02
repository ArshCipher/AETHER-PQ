// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file ml_kem.hpp
 * @brief ML-KEM (FIPS 203) implementation via liboqs.
 *
 * Supports all three parameter sets:
 *   Level::Kem512  — ML-KEM-512  (NIST security category 1, Lightweight profile)
 *   Level::Kem768  — ML-KEM-768  (NIST security category 3, Standard profile)
 *   Level::Kem1024 — ML-KEM-1024 (NIST security category 5, Hardened profile)
 *
 * Key sizes (public / private / ciphertext / shared secret):
 *   ML-KEM-512  : 800 / 1632 / 768 / 32 bytes
 *   ML-KEM-768  : 1184 / 2400 / 1088 / 32 bytes
 *   ML-KEM-1024 : 1568 / 3168 / 1568 / 32 bytes
 *
 * Thread safety: MlKem instances are immutable after construction.
 * Multiple threads may call generate_keypair/encapsulate/decapsulate concurrently
 * on the same instance — liboqs operations are stateless.
 */

#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <memory>
#include <string_view>

// Forward declare the OQS opaque type to avoid exposing oqs/ in public headers.
struct OQS_KEM;

namespace uav_pqc::crypto {

/**
 * @brief ML-KEM implementation wrapping liboqs OQS_KEM.
 *
 * RAII: the internal OQS_KEM context is freed in the destructor via a
 * custom deleter; callers never touch raw liboqs pointers.
 */
class MlKem final : public IKem {
public:
    /// ML-KEM parameter set selection.
    enum class Level {
        Kem512,  ///< ML-KEM-512  — Lightweight profile
        Kem768,  ///< ML-KEM-768  — Standard profile (default)
        Kem1024, ///< ML-KEM-1024 — Hardened profile
    };

    /**
     * @brief Construct an ML-KEM instance for the given security level.
     *
     * @param level  Parameter set.  Default: Kem768 (NIST category 3).
     * @throws std::runtime_error if liboqs cannot load the algorithm
     *         (indicates a build configuration problem, not a runtime error).
     */
    explicit MlKem(Level level = Level::Kem768);
    ~MlKem() override;

    MlKem(const MlKem&)            = delete;
    MlKem& operator=(const MlKem&) = delete;
    MlKem(MlKem&&) noexcept;
    MlKem& operator=(MlKem&&) noexcept;

    // ── IKem implementation ───────────────────────────────────────────────────

    [[nodiscard]] Result<KemKeyPair>          generate_keypair()                           const override;
    [[nodiscard]] Result<KemKeyPair>          generate_keypair_deterministic(ByteSpan seed) const override;
    [[nodiscard]] Result<EncapsulationResult> encapsulate(const KemPublicKey& pk)          const override;
    [[nodiscard]] Result<SharedSecret>        decapsulate(const KemPrivateKey& sk,
                                                          const KemCiphertext& ct)         const override;

    [[nodiscard]] std::string_view algorithm_id()       const noexcept override;
    [[nodiscard]] std::size_t      public_key_size()    const noexcept override;
    [[nodiscard]] std::size_t      private_key_size()   const noexcept override;
    [[nodiscard]] std::size_t      ciphertext_size()    const noexcept override;
    [[nodiscard]] std::size_t      shared_secret_size() const noexcept override;

    // ── MlKem-specific accessors ──────────────────────────────────────────────

    /// Returns the active security level.
    [[nodiscard]] Level level() const noexcept { return level_; }

    /// OQS method name string (e.g. "ML-KEM-768"), useful for logging.
    [[nodiscard]] static std::string_view oqs_method_name(Level level) noexcept;

private:
    Level level_;

    /// Custom deleter wraps OQS_KEM_free so unique_ptr works with an opaque type.
    struct OqsKemDeleter {
        void operator()(OQS_KEM* p) const noexcept;
    };
    std::unique_ptr<OQS_KEM, OqsKemDeleter> kem_;
};

} // namespace uav_pqc::crypto
