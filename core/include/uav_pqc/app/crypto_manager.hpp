// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/x25519.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/crypto/hkdf.hpp"

#include <mutex>
#include <optional>
#include <string>

namespace uav_pqc::app {

/**
 * @brief Abstract CryptoManager interface exposing complete suite of cryptographic operations.
 */
class ICryptoManager {
public:
    ICryptoManager() = default;
    virtual ~ICryptoManager() = default;

    ICryptoManager(const ICryptoManager&) = delete;
    ICryptoManager& operator=(const ICryptoManager&) = delete;
    ICryptoManager(ICryptoManager&&) noexcept = default;
    ICryptoManager& operator=(ICryptoManager&&) noexcept = default;

    // ── Random Number Generation ─────────────────────────────────────────────
    virtual Result<Bytes> generate_random_bytes(std::size_t size) = 0;

    // ── Key Generation ───────────────────────────────────────────────────────
    virtual Result<crypto::KemKeyPair> generate_kem_keypair() = 0; // default hybrid
    virtual Result<crypto::KemKeyPair> generate_ml_kem_keypair(crypto::MlKem::Level level) = 0;
    virtual Result<crypto::KemKeyPair> generate_x25519_keypair() = 0;
    virtual Result<crypto::KemKeyPair> generate_hybrid_kem_keypair() = 0;

    virtual Result<crypto::DsaKeyPair> generate_dsa_keypair() = 0; // default ML-DSA-65
    virtual Result<crypto::DsaKeyPair> generate_ml_dsa_keypair(crypto::MlDsa::Level level) = 0;
    virtual Result<crypto::DsaKeyPair> generate_ecdsa_p256_keypair() = 0;

    // ── Digital Signatures ───────────────────────────────────────────────────
    virtual Result<Bytes> sign_transcript(const Bytes& transcript) = 0; // default static ML-DSA-65
    virtual Result<bool> verify_transcript(const Bytes& transcript, const Bytes& signature, const crypto::DsaPublicKey& pub_key) = 0;

    virtual Result<Bytes> sign_ml_dsa(const crypto::DsaPrivateKey& sk, ByteSpan msg, crypto::MlDsa::Level level) = 0;
    virtual Result<bool> verify_ml_dsa(const crypto::DsaPublicKey& pk, ByteSpan msg, ByteSpan signature, crypto::MlDsa::Level level) = 0;

    virtual Result<Bytes> sign_ecdsa_p256(const crypto::DsaPrivateKey& sk, ByteSpan msg) = 0;
    virtual Result<bool> verify_ecdsa_p256(const crypto::DsaPublicKey& pk, ByteSpan msg, ByteSpan signature) = 0;

    // ── Key Encapsulation (KEM) ──────────────────────────────────────────────
    virtual Result<crypto::SharedSecret> decapsulate_secret(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct) = 0; // default hybrid
    virtual Result<crypto::EncapsulationResult> encapsulate_secret(const crypto::KemPublicKey& pk) = 0;

    virtual Result<crypto::SharedSecret> decapsulate_ml_kem(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct, crypto::MlKem::Level level) = 0;
    virtual Result<crypto::EncapsulationResult> encapsulate_ml_kem(const crypto::KemPublicKey& pk, crypto::MlKem::Level level) = 0;

    virtual Result<crypto::SharedSecret> decapsulate_x25519(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct) = 0;
    virtual Result<crypto::EncapsulationResult> encapsulate_x25519(const crypto::KemPublicKey& pk) = 0;

    // ── Key Derivation (HKDF) ────────────────────────────────────────────────
    virtual Result<SecureBytes> hkdf_sha256_extract_and_expand(ByteSpan salt, ByteSpan ikm, ByteSpan info, std::size_t out_len) = 0;

    // ── Symmetric Cryptography (AEAD) ────────────────────────────────────────
    virtual Result<Bytes> aes_gcm_encrypt(ByteSpan plaintext, ByteSpan key, ByteSpan iv, ByteSpan aad) = 0;
    virtual Result<Bytes> aes_gcm_decrypt(ByteSpan ciphertext, ByteSpan key, ByteSpan iv, ByteSpan aad) = 0;

    virtual Result<Bytes> chacha20_poly1305_encrypt(ByteSpan plaintext, ByteSpan key, ByteSpan iv, ByteSpan aad) = 0;
    virtual Result<Bytes> chacha20_poly1305_decrypt(ByteSpan ciphertext, ByteSpan key, ByteSpan iv, ByteSpan aad) = 0;

    // ── PEM & Serialization Support ──────────────────────────────────────────
    virtual Result<std::string> export_dsa_private_key_to_pem(const crypto::DsaPrivateKey& sk, bool is_ecdsa) = 0;
    virtual Result<std::string> export_dsa_public_key_to_pem(const crypto::DsaPublicKey& pk, bool is_ecdsa) = 0;
    virtual Result<crypto::DsaKeyPair> import_dsa_keypair_from_pem(const std::string& private_pem, const std::string& public_pem, bool is_ecdsa) = 0;

    // ── Static DSA Key pair management ───────────────────────────────────────
    virtual void set_static_dsa_keypair(crypto::DsaKeyPair keypair) = 0;
    virtual const std::optional<crypto::DsaKeyPair>& get_static_dsa_keypair() const noexcept = 0;

    // ── Memory Protection / Zeroization ──────────────────────────────────────
    virtual void clean_sensitive_memory(MutableByteSpan span) noexcept = 0;
};

/**
 * @brief Concrete CryptoManager implementing the full ICryptoManager using liboqs and OpenSSL.
 */
class CryptoManager final : public ICryptoManager {
public:
    CryptoManager();
    ~CryptoManager() override = default;

    Result<Bytes> generate_random_bytes(std::size_t size) override;

    Result<crypto::KemKeyPair> generate_kem_keypair() override;
    Result<crypto::KemKeyPair> generate_ml_kem_keypair(crypto::MlKem::Level level) override;
    Result<crypto::KemKeyPair> generate_x25519_keypair() override;
    Result<crypto::KemKeyPair> generate_hybrid_kem_keypair() override;

    Result<crypto::DsaKeyPair> generate_dsa_keypair() override;
    Result<crypto::DsaKeyPair> generate_ml_dsa_keypair(crypto::MlDsa::Level level) override;
    Result<crypto::DsaKeyPair> generate_ecdsa_p256_keypair() override;

    Result<Bytes> sign_transcript(const Bytes& transcript) override;
    Result<bool> verify_transcript(const Bytes& transcript, const Bytes& signature, const crypto::DsaPublicKey& pub_key) override;

    Result<Bytes> sign_ml_dsa(const crypto::DsaPrivateKey& sk, ByteSpan msg, crypto::MlDsa::Level level) override;
    Result<bool> verify_ml_dsa(const crypto::DsaPublicKey& pk, ByteSpan msg, ByteSpan signature, crypto::MlDsa::Level level) override;

    Result<Bytes> sign_ecdsa_p256(const crypto::DsaPrivateKey& sk, ByteSpan msg) override;
    Result<bool> verify_ecdsa_p256(const crypto::DsaPublicKey& pk, ByteSpan msg, ByteSpan signature) override;

    Result<crypto::SharedSecret> decapsulate_secret(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct) override;
    Result<crypto::EncapsulationResult> encapsulate_secret(const crypto::KemPublicKey& pk) override;

    Result<crypto::SharedSecret> decapsulate_ml_kem(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct, crypto::MlKem::Level level) override;
    Result<crypto::EncapsulationResult> encapsulate_ml_kem(const crypto::KemPublicKey& pk, crypto::MlKem::Level level) override;

    Result<crypto::SharedSecret> decapsulate_x25519(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct) override;
    Result<crypto::EncapsulationResult> encapsulate_x25519(const crypto::KemPublicKey& pk) override;

    Result<SecureBytes> hkdf_sha256_extract_and_expand(ByteSpan salt, ByteSpan ikm, ByteSpan info, std::size_t out_len) override;

    Result<Bytes> aes_gcm_encrypt(ByteSpan plaintext, ByteSpan key, ByteSpan iv, ByteSpan aad) override;
    Result<Bytes> aes_gcm_decrypt(ByteSpan ciphertext, ByteSpan key, ByteSpan iv, ByteSpan aad) override;

    Result<Bytes> chacha20_poly1305_encrypt(ByteSpan plaintext, ByteSpan key, ByteSpan iv, ByteSpan aad) override;
    Result<Bytes> chacha20_poly1305_decrypt(ByteSpan ciphertext, ByteSpan key, ByteSpan iv, ByteSpan aad) override;

    Result<std::string> export_dsa_private_key_to_pem(const crypto::DsaPrivateKey& sk, bool is_ecdsa) override;
    Result<std::string> export_dsa_public_key_to_pem(const crypto::DsaPublicKey& pk, bool is_ecdsa) override;
    Result<crypto::DsaKeyPair> import_dsa_keypair_from_pem(const std::string& private_pem, const std::string& public_pem, bool is_ecdsa) override;

    void set_static_dsa_keypair(crypto::DsaKeyPair keypair) override;
    const std::optional<crypto::DsaKeyPair>& get_static_dsa_keypair() const noexcept override { return static_dsa_keypair_; }

    void clean_sensitive_memory(MutableByteSpan span) noexcept override;

private:
    std::mutex mutex_;
    std::optional<crypto::DsaKeyPair> static_dsa_keypair_;
};

} // namespace uav_pqc::app
