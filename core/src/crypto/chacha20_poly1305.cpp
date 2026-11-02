// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file chacha20_poly1305.cpp
 * @brief ChaCha20-Poly1305 AEAD via OpenSSL 3 EVP_chacha20_poly1305().
 */

#include "uav_pqc/crypto/chacha20_poly1305.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <openssl/evp.h>

namespace uav_pqc::crypto {

using uav_pqc::secure_zero;

namespace {
struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
} // anonymous namespace

// ── Metadata ──────────────────────────────────────────────────────────────────

std::string_view ChaCha20Poly1305::algorithm_id() const noexcept { return "ChaCha20-Poly1305"; }
std::size_t      ChaCha20Poly1305::key_size()     const noexcept { return kKeySize; }
std::size_t      ChaCha20Poly1305::nonce_size()   const noexcept { return kNonceSize; }
std::size_t      ChaCha20Poly1305::tag_size()     const noexcept { return kTagSize; }

// ── encrypt ───────────────────────────────────────────────────────────────────

Result<Bytes> ChaCha20Poly1305::encrypt(const AeadKey& key, ByteSpan nonce,
                                         ByteSpan plaintext, ByteSpan aad) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::ChaCha20);
    if (key.data.size() != kKeySize) {
        return err<Bytes>(ErrorCode::InvalidArgument,
            "ChaCha20-Poly1305 encrypt: key must be 32 bytes");
    }
    if (nonce.size() != kNonceSize) {
        return err<Bytes>(ErrorCode::InvalidArgument,
            "ChaCha20-Poly1305 encrypt: nonce must be 12 bytes");
    }

    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) return err<Bytes>(ErrorCode::AeadEncryptFailed, "EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceSize), nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data.data()),
            reinterpret_cast<const unsigned char*>(nonce.data())) <= 0) {
        return err<Bytes>(ErrorCode::AeadEncryptFailed, "ChaCha20-Poly1305 EncryptInit failed");
    }

    if (!aad.empty()) {
        int tmp = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &tmp,
                reinterpret_cast<const unsigned char*>(aad.data()),
                static_cast<int>(aad.size())) <= 0) {
            return err<Bytes>(ErrorCode::AeadEncryptFailed, "ChaCha20 AAD failed");
        }
    }

    Bytes out(plaintext.size() + kTagSize);
    int len = 0, final_len = 0;

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(),
                reinterpret_cast<unsigned char*>(out.data()), &len,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())) <= 0) {
            return err<Bytes>(ErrorCode::AeadEncryptFailed, "ChaCha20 EncryptUpdate failed");
        }
    }
    if (EVP_EncryptFinal_ex(ctx.get(),
            reinterpret_cast<unsigned char*>(out.data()) + len, &final_len) <= 0) {
        return err<Bytes>(ErrorCode::AeadEncryptFailed, "ChaCha20 EncryptFinal failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
            static_cast<int>(kTagSize),
            reinterpret_cast<unsigned char*>(out.data()) + len + final_len) <= 0) {
        return err<Bytes>(ErrorCode::AeadEncryptFailed, "ChaCha20 get tag failed");
    }
    out.resize(static_cast<std::size_t>(len + final_len) + kTagSize);
    return ok<Bytes>(std::move(out));
}

// ── decrypt ───────────────────────────────────────────────────────────────────

Result<Bytes> ChaCha20Poly1305::decrypt(const AeadKey& key, ByteSpan nonce,
                                         ByteSpan ciphertext, ByteSpan aad) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::ChaCha20);
    if (ciphertext.size() < kTagSize) {
        return err<Bytes>(ErrorCode::AeadDecryptFailed,
            "ChaCha20-Poly1305 decrypt: ciphertext too short");
    }
    if (key.data.size() != kKeySize) {
        return err<Bytes>(ErrorCode::InvalidArgument,
            "ChaCha20-Poly1305 decrypt: key must be 32 bytes");
    }
    if (nonce.size() != kNonceSize) {
        return err<Bytes>(ErrorCode::InvalidArgument,
            "ChaCha20-Poly1305 decrypt: nonce must be 12 bytes");
    }

    const std::size_t body_len = ciphertext.size() - kTagSize;

    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) return err<Bytes>(ErrorCode::AeadDecryptFailed, "EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceSize), nullptr) <= 0 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data.data()),
            reinterpret_cast<const unsigned char*>(nonce.data())) <= 0) {
        return err<Bytes>(ErrorCode::AeadDecryptFailed, "ChaCha20 DecryptInit failed");
    }

    if (!aad.empty()) {
        int tmp = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &tmp,
                reinterpret_cast<const unsigned char*>(aad.data()),
                static_cast<int>(aad.size())) <= 0) {
            return err<Bytes>(ErrorCode::AeadDecryptFailed, "ChaCha20 AAD failed");
        }
    }

    Bytes plaintext(body_len);
    int len = 0;
    if (body_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(),
                reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                reinterpret_cast<const unsigned char*>(ciphertext.data()),
                static_cast<int>(body_len)) <= 0) {
            secure_zero(MutableByteSpan{plaintext.data(), plaintext.size()});
            return err<Bytes>(ErrorCode::AeadDecryptFailed, "ChaCha20 DecryptUpdate failed");
        }
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    void* tag_ptr = const_cast<std::byte*>(ciphertext.data() + body_len);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
            static_cast<int>(kTagSize), tag_ptr) <= 0) {
        secure_zero(MutableByteSpan{plaintext.data(), plaintext.size()});
        return err<Bytes>(ErrorCode::AeadDecryptFailed, "ChaCha20 set tag failed");
    }

    int final_len = 0;
    const int tag_ok = EVP_DecryptFinal_ex(ctx.get(),
        reinterpret_cast<unsigned char*>(plaintext.data()) + len, &final_len);

    if (tag_ok <= 0) {
        secure_zero(MutableByteSpan{plaintext.data(), plaintext.size()});
        UAV_PQC_LOG_WARN("crypto.chacha20", "Poly1305 tag verification FAILED");
        return err<Bytes>(ErrorCode::AeadDecryptFailed,
                          "ChaCha20-Poly1305 authentication tag mismatch");
    }

    plaintext.resize(static_cast<std::size_t>(len + final_len));
    return ok<Bytes>(std::move(plaintext));
}

} // namespace uav_pqc::crypto
