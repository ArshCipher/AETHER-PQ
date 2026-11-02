// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"

#include <memory>
#include <string_view>
#include <initializer_list>

namespace uav_pqc::crypto {

class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;

    // ── Random Number Generation ─────────────────────────────────────────────
    [[nodiscard]] virtual Result<Bytes> generate_random_bytes(std::size_t size) const = 0;

    // ── Key Encapsulation Mechanisms (KEM) ───────────────────────────────────
    [[nodiscard]] virtual std::unique_ptr<IKem> create_ml_kem(MlKem::Level level) const = 0;
    [[nodiscard]] virtual std::unique_ptr<IKem> create_x25519_kem() const = 0;
    [[nodiscard]] virtual std::unique_ptr<IKem> create_hybrid_kem(std::string_view context = "uav_pqc|hybrid|kem|v1") const = 0;

    // ── Digital Signature Algorithms (DSA) ───────────────────────────────────
    [[nodiscard]] virtual std::unique_ptr<IDsa> create_ml_dsa(MlDsa::Level level) const = 0;
    [[nodiscard]] virtual std::unique_ptr<IDsa> create_ecdsa_p256() const = 0;

    // ── Symmetric Encryption (AEAD) ──────────────────────────────────────────
    [[nodiscard]] virtual std::unique_ptr<IAead> create_aes_gcm(AesKeyLen key_len) const = 0;
    [[nodiscard]] virtual std::unique_ptr<IAead> create_chacha20_poly1305() const = 0;

    // ── Key Derivation Functions (KDF) ───────────────────────────────────────
    [[nodiscard]] virtual Result<SecureBytes> hkdf_extract(HkdfHash hash, ByteSpan salt, ByteSpan ikm) const = 0;
    [[nodiscard]] virtual Result<SecureBytes> hkdf_expand(HkdfHash hash, ByteSpan prk, ByteSpan info, std::size_t length) const = 0;
    [[nodiscard]] virtual Result<SecureBytes> hkdf_derive(HkdfHash hash, ByteSpan salt, ByteSpan ikm, ByteSpan info, std::size_t length) const = 0;

    // ── Hash Functions ───────────────────────────────────────────────────────
    [[nodiscard]] virtual Result<Bytes> hash_sha256(ByteSpan data) const = 0;
    [[nodiscard]] virtual Result<Bytes> hash_sha256_multi(std::initializer_list<ByteSpan> spans) const = 0;
};

} // namespace uav_pqc::crypto
