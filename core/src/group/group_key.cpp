// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file group_key.cpp
 * @brief GroupKey class implementation.
 */

#include "uav_pqc/group/group_key.hpp"
#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/crypto/chacha20_poly1305.hpp"
#include "uav_pqc/crypto/provider.hpp"

namespace uav_pqc::group {

GroupKey::GroupKey(GroupEpoch              epoch,
                   SecureBytes             key_bytes,
                   protocol::AeadAlgorithm algorithm,
                   Timestamp               issued_ms,
                   Timestamp               expiry_ms)
    : epoch_(epoch),
      key_bytes_(std::move(key_bytes)),
      algorithm_(algorithm),
      issued_ms_(issued_ms),
      expiry_ms_(expiry_ms) {}

GroupKey GroupKey::clone() const {
    return GroupKey(epoch_, SecureBytes(Bytes(key_bytes_.bytes())), algorithm_, issued_ms_, expiry_ms_);
}

Result<Bytes> GroupKey::encrypt(ByteSpan plaintext, ByteSpan aad, std::uint64_t message_counter, const crypto::ICryptoProvider* provider) const {
    std::array<std::byte, 12> nonce{};
    nonce[0] = static_cast<std::byte>((epoch_ >> 24) & 0xFFu);
    nonce[1] = static_cast<std::byte>((epoch_ >> 16) & 0xFFu);
    nonce[2] = static_cast<std::byte>((epoch_ >> 8) & 0xFFu);
    nonce[3] = static_cast<std::byte>(epoch_ & 0xFFu);

    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<std::byte>((message_counter >> ((7 - i) * 8)) & 0xFFu);
    }

    crypto::AeadKey key;
    key.data = SecureBytes(Bytes(key_bytes_.bytes()));

    std::unique_ptr<crypto::IAead> aead;
    if (provider) {
        if (algorithm_ == protocol::AeadAlgorithm::AesGcm256) {
            aead = provider->create_aes_gcm(crypto::AesKeyLen::Aes256);
        } else if (algorithm_ == protocol::AeadAlgorithm::ChaCha20Poly) {
            aead = provider->create_chacha20_poly1305();
        }
    } else {
        if (algorithm_ == protocol::AeadAlgorithm::AesGcm256) {
            aead = std::make_unique<crypto::AesGcm>(crypto::AesKeyLen::Aes256);
        } else if (algorithm_ == protocol::AeadAlgorithm::ChaCha20Poly) {
            aead = std::make_unique<crypto::ChaCha20Poly1305>();
        }
    }

    if (aead) {
        return aead->encrypt(key, ByteSpan{nonce.data(), 12}, plaintext, aad);
    }

    return err<Bytes>(ErrorCode::UnsupportedAlgorithm, "Unsupported group key AEAD algorithm");
}

Result<Bytes> GroupKey::decrypt(ByteSpan ciphertext, ByteSpan aad, std::uint64_t message_counter, const crypto::ICryptoProvider* provider) const {
    std::array<std::byte, 12> nonce{};
    nonce[0] = static_cast<std::byte>((epoch_ >> 24) & 0xFFu);
    nonce[1] = static_cast<std::byte>((epoch_ >> 16) & 0xFFu);
    nonce[2] = static_cast<std::byte>((epoch_ >> 8) & 0xFFu);
    nonce[3] = static_cast<std::byte>(epoch_ & 0xFFu);

    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<std::byte>((message_counter >> ((7 - i) * 8)) & 0xFFu);
    }

    crypto::AeadKey key;
    key.data = SecureBytes(Bytes(key_bytes_.bytes()));

    std::unique_ptr<crypto::IAead> aead;
    if (provider) {
        if (algorithm_ == protocol::AeadAlgorithm::AesGcm256) {
            aead = provider->create_aes_gcm(crypto::AesKeyLen::Aes256);
        } else if (algorithm_ == protocol::AeadAlgorithm::ChaCha20Poly) {
            aead = provider->create_chacha20_poly1305();
        }
    } else {
        if (algorithm_ == protocol::AeadAlgorithm::AesGcm256) {
            aead = std::make_unique<crypto::AesGcm>(crypto::AesKeyLen::Aes256);
        } else if (algorithm_ == protocol::AeadAlgorithm::ChaCha20Poly) {
            aead = std::make_unique<crypto::ChaCha20Poly1305>();
        }
    }

    if (aead) {
        return aead->decrypt(key, ByteSpan{nonce.data(), 12}, ciphertext, aad);
    }

    return err<Bytes>(ErrorCode::UnsupportedAlgorithm, "Unsupported group key AEAD algorithm");
}

crypto::AeadKey GroupKey::make_aead_key() const {
    crypto::AeadKey key;
    key.data = SecureBytes(Bytes(key_bytes_.bytes()));
    return key;
}

} // namespace uav_pqc::group
