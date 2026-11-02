// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file aes_gcm.cpp
 * @brief AES-GCM AEAD via OpenSSL 3 EVP_EncryptInit / EVP_DecryptInit.
 */

#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <openssl/evp.h>

#include <cstring>

namespace uav_pqc::crypto {

using uav_pqc::secure_zero;

namespace {

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

/// Returns the correct EVP_CIPHER for this key length.
const EVP_CIPHER* select_cipher(AesKeyLen len) noexcept {
    return (len == AesKeyLen::Aes256) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
}

} // anonymous namespace

// ── Constructor ───────────────────────────────────────────────────────────────

AesGcm::AesGcm(AesKeyLen key_len) : key_len_(key_len) {}

// ── Metadata ──────────────────────────────────────────────────────────────────

std::string_view AesGcm::algorithm_id() const noexcept {
    return (key_len_ == AesKeyLen::Aes256) ? "AES-256-GCM" : "AES-128-GCM";
}
std::size_t AesGcm::key_size()   const noexcept { return (key_len_ == AesKeyLen::Aes256) ? 32 : 16; }
std::size_t AesGcm::nonce_size() const noexcept { return kNonceSize; }
std::size_t AesGcm::tag_size()   const noexcept { return kTagSize; }

// ── encrypt ───────────────────────────────────────────────────────────────────

Result<Bytes> AesGcm::encrypt(const AeadKey& key, ByteSpan nonce,
                               ByteSpan plaintext, ByteSpan aad) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::AesGcm);
    if (key.data.size() != key_size()) {
        return err<Bytes>(ErrorCode::InvalidArgument,
            "AES-GCM encrypt: key size mismatch");
    }
    if (nonce.size() != kNonceSize) {
        return err<Bytes>(ErrorCode::InvalidArgument,
            "AES-GCM encrypt: nonce must be 12 bytes");
    }

    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) return err<Bytes>(ErrorCode::AeadEncryptFailed, "EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx.get(), select_cipher(key_len_), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize), nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data.data()),
            reinterpret_cast<const unsigned char*>(nonce.data())) <= 0) {
        return err<Bytes>(ErrorCode::AeadEncryptFailed, "AES-GCM EncryptInit failed");
    }

    // Authenticate additional data
    if (!aad.empty()) {
        int aad_len_out = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len_out,
                reinterpret_cast<const unsigned char*>(aad.data()),
                static_cast<int>(aad.size())) <= 0) {
            return err<Bytes>(ErrorCode::AeadEncryptFailed, "AES-GCM AAD update failed");
        }
    }

    Bytes ciphertext(plaintext.size() + kTagSize);
    int len = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(),
                reinterpret_cast<unsigned char*>(ciphertext.data()),
                &len,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())) <= 0) {
            return err<Bytes>(ErrorCode::AeadEncryptFailed, "AES-GCM EncryptUpdate failed");
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(),
            reinterpret_cast<unsigned char*>(ciphertext.data()) + len, &final_len) <= 0) {
        return err<Bytes>(ErrorCode::AeadEncryptFailed, "AES-GCM EncryptFinal failed");
    }

    // Append authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
            static_cast<int>(kTagSize),
            reinterpret_cast<unsigned char*>(ciphertext.data()) + len + final_len) <= 0) {
        return err<Bytes>(ErrorCode::AeadEncryptFailed, "AES-GCM get tag failed");
    }

    ciphertext.resize(static_cast<std::size_t>(len + final_len) + kTagSize);
    return ok<Bytes>(std::move(ciphertext));
}

// ── decrypt ───────────────────────────────────────────────────────────────────

Result<Bytes> AesGcm::decrypt(const AeadKey& key, ByteSpan nonce,
                               ByteSpan ciphertext, ByteSpan aad) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::AesGcm);
    if (ciphertext.size() < kTagSize) {
        return err<Bytes>(ErrorCode::AeadDecryptFailed,
            "AES-GCM decrypt: ciphertext too short");
    }
    if (key.data.size() != key_size()) {
        return err<Bytes>(ErrorCode::InvalidArgument, "AES-GCM decrypt: key size mismatch");
    }
    if (nonce.size() != kNonceSize) {
        return err<Bytes>(ErrorCode::InvalidArgument, "AES-GCM decrypt: nonce must be 12 bytes");
    }

    const std::size_t body_len = ciphertext.size() - kTagSize;

    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) return err<Bytes>(ErrorCode::AeadDecryptFailed, "EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx.get(), select_cipher(key_len_), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize), nullptr) <= 0 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data.data()),
            reinterpret_cast<const unsigned char*>(nonce.data())) <= 0) {
        return err<Bytes>(ErrorCode::AeadDecryptFailed, "AES-GCM DecryptInit failed");
    }

    // Authenticate additional data
    if (!aad.empty()) {
        int aad_len = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len,
                reinterpret_cast<const unsigned char*>(aad.data()),
                static_cast<int>(aad.size())) <= 0) {
            return err<Bytes>(ErrorCode::AeadDecryptFailed, "AES-GCM AAD update failed");
        }
    }

    Bytes plaintext(body_len);
    int len = 0;
    if (body_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(),
                reinterpret_cast<unsigned char*>(plaintext.data()),
                &len,
                reinterpret_cast<const unsigned char*>(ciphertext.data()),
                static_cast<int>(body_len)) <= 0) {
            secure_zero(MutableByteSpan{plaintext.data(), plaintext.size()});
            return err<Bytes>(ErrorCode::AeadDecryptFailed, "AES-GCM DecryptUpdate failed");
        }
    }

    // Set the expected tag
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    void* tag_ptr = const_cast<std::byte*>(ciphertext.data() + body_len);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(kTagSize), tag_ptr) <= 0) {
        secure_zero(MutableByteSpan{plaintext.data(), plaintext.size()});
        return err<Bytes>(ErrorCode::AeadDecryptFailed, "AES-GCM set tag failed");
    }

    int final_len = 0;
    const int tag_ok = EVP_DecryptFinal_ex(ctx.get(),
        reinterpret_cast<unsigned char*>(plaintext.data()) + len, &final_len);

    if (tag_ok <= 0) {
        // Authentication tag mismatch — zero the plaintext before returning
        secure_zero(MutableByteSpan{plaintext.data(), plaintext.size()});
        UAV_PQC_LOG_WARN("crypto.aes_gcm", "Authentication tag verification FAILED");
        return err<Bytes>(ErrorCode::AeadDecryptFailed,
                          "AES-GCM authentication tag mismatch");
    }

    plaintext.resize(static_cast<std::size_t>(len + final_len));
    return ok<Bytes>(std::move(plaintext));
}

} // namespace uav_pqc::crypto
