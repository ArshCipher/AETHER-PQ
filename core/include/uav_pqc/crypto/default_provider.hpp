// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/crypto/provider.hpp"

namespace uav_pqc::crypto {

class DefaultCryptoProvider final : public ICryptoProvider {
public:
    DefaultCryptoProvider() = default;
    ~DefaultCryptoProvider() override = default;

    [[nodiscard]] Result<Bytes> generate_random_bytes(std::size_t size) const override;

    [[nodiscard]] std::unique_ptr<IKem> create_ml_kem(MlKem::Level level) const override;
    [[nodiscard]] std::unique_ptr<IKem> create_x25519_kem() const override;
    [[nodiscard]] std::unique_ptr<IKem> create_hybrid_kem(std::string_view context = "uav_pqc|hybrid|kem|v1") const override;

    [[nodiscard]] std::unique_ptr<IDsa> create_ml_dsa(MlDsa::Level level) const override;
    [[nodiscard]] std::unique_ptr<IDsa> create_ecdsa_p256() const override;

    [[nodiscard]] std::unique_ptr<IAead> create_aes_gcm(AesKeyLen key_len) const override;
    [[nodiscard]] std::unique_ptr<IAead> create_chacha20_poly1305() const override;

    [[nodiscard]] Result<SecureBytes> hkdf_extract(HkdfHash hash, ByteSpan salt, ByteSpan ikm) const override;
    [[nodiscard]] Result<SecureBytes> hkdf_expand(HkdfHash hash, ByteSpan prk, ByteSpan info, std::size_t length) const override;
    [[nodiscard]] Result<SecureBytes> hkdf_derive(HkdfHash hash, ByteSpan salt, ByteSpan ikm, ByteSpan info, std::size_t length) const override;

    [[nodiscard]] Result<Bytes> hash_sha256(ByteSpan data) const override;
    [[nodiscard]] Result<Bytes> hash_sha256_multi(std::initializer_list<ByteSpan> spans) const override;
};

} // namespace uav_pqc::crypto
