// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/crypto/default_provider.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/x25519.hpp"
#include "uav_pqc/crypto/hybrid_kem.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/crypto/chacha20_poly1305.hpp"
#include "uav_pqc/crypto/hkdf.hpp"

#include <openssl/rand.h>
#include <openssl/evp.h>

namespace uav_pqc::crypto {

Result<Bytes> DefaultCryptoProvider::generate_random_bytes(std::size_t size) const {
    Bytes buf(size);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), static_cast<int>(size)) != 1) {
        return err<Bytes>(ErrorCode::InternalError, "OpenSSL RAND_bytes failed");
    }
    return ok<Bytes>(std::move(buf));
}

std::unique_ptr<IKem> DefaultCryptoProvider::create_ml_kem(MlKem::Level level) const {
    return std::make_unique<MlKem>(level);
}

std::unique_ptr<IKem> DefaultCryptoProvider::create_x25519_kem() const {
    return std::make_unique<X25519Kem>();
}

std::unique_ptr<IKem> DefaultCryptoProvider::create_hybrid_kem(std::string_view context) const {
    return std::make_unique<HybridKem>(context);
}

std::unique_ptr<IDsa> DefaultCryptoProvider::create_ml_dsa(MlDsa::Level level) const {
    return std::make_unique<MlDsa>(level);
}

std::unique_ptr<IDsa> DefaultCryptoProvider::create_ecdsa_p256() const {
    return std::make_unique<EcdsaP256>();
}

std::unique_ptr<IAead> DefaultCryptoProvider::create_aes_gcm(AesKeyLen key_len) const {
    return std::make_unique<AesGcm>(key_len);
}

std::unique_ptr<IAead> DefaultCryptoProvider::create_chacha20_poly1305() const {
    return std::make_unique<ChaCha20Poly1305>();
}

Result<SecureBytes> DefaultCryptoProvider::hkdf_extract(HkdfHash hash, ByteSpan salt, ByteSpan ikm) const {
    Hkdf hkdf(hash);
    return hkdf.extract(salt, ikm);
}

Result<SecureBytes> DefaultCryptoProvider::hkdf_expand(HkdfHash hash, ByteSpan prk, ByteSpan info, std::size_t length) const {
    Hkdf hkdf(hash);
    return hkdf.expand(prk, info, length);
}

Result<SecureBytes> DefaultCryptoProvider::hkdf_derive(HkdfHash hash, ByteSpan salt, ByteSpan ikm, ByteSpan info, std::size_t length) const {
    Hkdf hkdf(hash);
    return hkdf.derive(salt, ikm, info, length);
}

Result<Bytes> DefaultCryptoProvider::hash_sha256(ByteSpan data) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return err<Bytes>(ErrorCode::InternalError, "EVP_MD_CTX_new failed");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) <= 0 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return err<Bytes>(ErrorCode::InternalError, "SHA256 update failed");
    }
    Bytes out(32);
    unsigned int len = 32;
    if (EVP_DigestFinal_ex(ctx, reinterpret_cast<unsigned char*>(out.data()), &len) <= 0) {
        EVP_MD_CTX_free(ctx);
        return err<Bytes>(ErrorCode::InternalError, "SHA256 final failed");
    }
    EVP_MD_CTX_free(ctx);
    return ok<Bytes>(std::move(out));
}

Result<Bytes> DefaultCryptoProvider::hash_sha256_multi(std::initializer_list<ByteSpan> spans) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return err<Bytes>(ErrorCode::InternalError, "EVP_MD_CTX_new failed");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) <= 0) {
        EVP_MD_CTX_free(ctx);
        return err<Bytes>(ErrorCode::InternalError, "SHA256 init failed");
    }
    for (const auto& span : spans) {
        if (EVP_DigestUpdate(ctx, span.data(), span.size()) <= 0) {
            EVP_MD_CTX_free(ctx);
            return err<Bytes>(ErrorCode::InternalError, "SHA256 update failed");
        }
    }
    Bytes out(32);
    unsigned int len = 32;
    if (EVP_DigestFinal_ex(ctx, reinterpret_cast<unsigned char*>(out.data()), &len) <= 0) {
        EVP_MD_CTX_free(ctx);
        return err<Bytes>(ErrorCode::InternalError, "SHA256 final failed");
    }
    EVP_MD_CTX_free(ctx);
    return ok<Bytes>(std::move(out));
}

} // namespace uav_pqc::crypto
