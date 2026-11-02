// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/crypto_manager.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/x25519.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/crypto/hybrid_kem.hpp"
#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/crypto/chacha20_poly1305.hpp"
#include "uav_pqc/crypto/hkdf.hpp"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cctype>
#include <algorithm>

namespace uav_pqc::app {

namespace {

std::string base64_encode(ByteSpan bytes) {
    std::size_t out_len = ((bytes.size() + 2) / 3) * 4;
    std::string out(out_len, '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                    reinterpret_cast<const unsigned char*>(bytes.data()),
                    static_cast<int>(bytes.size()));
    return out;
}

Result<Bytes> base64_decode(std::string_view b64) {
    std::string clean;
    clean.reserve(b64.size());
    for (char c : b64) {
        if (!std::isspace(c)) clean.push_back(c);
    }
    std::size_t padding = 0;
    if (!clean.empty() && clean.back() == '=') {
        padding++;
        if (clean.size() > 1 && clean[clean.size() - 2] == '=') {
            padding++;
        }
    }
    std::size_t raw_len = (clean.size() / 4) * 3;
    Bytes out(raw_len);
    int decoded_len = EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(clean.data()),
        static_cast<int>(clean.size()));
    if (decoded_len < 0) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Base64 decode failed");
    }
    out.resize(static_cast<std::size_t>(decoded_len) - padding);
    return ok<Bytes>(std::move(out));
}

std::string to_pem(std::string_view label, ByteSpan data) {
    std::string b64 = base64_encode(data);
    std::string pem = "-----BEGIN " + std::string(label) + "-----\n";
    for (std::size_t i = 0; i < b64.size(); i += 64) {
        pem += b64.substr(i, 64) + "\n";
    }
    pem += "-----END " + std::string(label) + "-----\n";
    return pem;
}

Result<Bytes> from_pem(std::string_view label, std::string_view pem) {
    std::string begin_str = "-----BEGIN " + std::string(label) + "-----";
    std::string end_str = "-----END " + std::string(label) + "-----";
    auto start = pem.find(begin_str);
    if (start == std::string::npos) {
        return err<Bytes>(ErrorCode::InvalidArgument, "PEM header not found");
    }
    auto end = pem.find(end_str, start);
    if (end == std::string::npos) {
        return err<Bytes>(ErrorCode::InvalidArgument, "PEM footer not found");
    }
    start += begin_str.size();
    std::string_view b64 = pem.substr(start, end - start);
    return base64_decode(b64);
}

} // namespace

CryptoManager::CryptoManager() = default;

Result<Bytes> CryptoManager::generate_random_bytes(std::size_t size) {
    Bytes buf(size);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), static_cast<int>(size)) != 1) {
        return err<Bytes>(ErrorCode::InternalError, "OpenSSL RAND_bytes failed");
    }
    return ok<Bytes>(std::move(buf));
}

Result<crypto::KemKeyPair> CryptoManager::generate_kem_keypair() {
    return generate_hybrid_kem_keypair();
}

Result<crypto::KemKeyPair> CryptoManager::generate_ml_kem_keypair(crypto::MlKem::Level level) {
    crypto::MlKem kem(level);
    return kem.generate_keypair();
}

Result<crypto::KemKeyPair> CryptoManager::generate_x25519_keypair() {
    crypto::X25519Kem kem;
    return kem.generate_keypair();
}

Result<crypto::KemKeyPair> CryptoManager::generate_hybrid_kem_keypair() {
    crypto::HybridKem kem;
    return kem.generate_keypair();
}

Result<crypto::DsaKeyPair> CryptoManager::generate_dsa_keypair() {
    return generate_ml_dsa_keypair(crypto::MlDsa::Level::Dsa65);
}

Result<crypto::DsaKeyPair> CryptoManager::generate_ml_dsa_keypair(crypto::MlDsa::Level level) {
    crypto::MlDsa dsa(level);
    return dsa.generate_keypair();
}

Result<crypto::DsaKeyPair> CryptoManager::generate_ecdsa_p256_keypair() {
    crypto::EcdsaP256 dsa;
    return dsa.generate_keypair();
}

Result<Bytes> CryptoManager::sign_transcript(const Bytes& transcript) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!static_dsa_keypair_) {
        return err<Bytes>(ErrorCode::SigningFailed, "No static DSA key pair loaded");
    }
    // ML-DSA verification uses ML-DSA-65 by default
    crypto::MlDsa dsa(crypto::MlDsa::Level::Dsa65);
    auto sig_r = dsa.sign(static_dsa_keypair_->private_key, ByteSpan{transcript.data(), transcript.size()});
    if (!sig_r) return err<Bytes>(sig_r.error());
    return ok<Bytes>(sig_r.value().data);
}

Result<bool> CryptoManager::verify_transcript(const Bytes& transcript, const Bytes& signature, const crypto::DsaPublicKey& pub_key) {
    crypto::MlDsa dsa(crypto::MlDsa::Level::Dsa65);
    crypto::Signature sig;
    sig.data = signature;
    auto res = dsa.verify(pub_key, ByteSpan{transcript.data(), transcript.size()}, sig);
    if (!res) return err<bool>(res.error());
    return ok<bool>(res.value());
}

Result<Bytes> CryptoManager::sign_ml_dsa(const crypto::DsaPrivateKey& sk, ByteSpan msg, crypto::MlDsa::Level level) {
    crypto::MlDsa dsa(level);
    auto sig_r = dsa.sign(sk, msg);
    if (!sig_r) return err<Bytes>(sig_r.error());
    return ok<Bytes>(sig_r.value().data);
}

Result<bool> CryptoManager::verify_ml_dsa(const crypto::DsaPublicKey& pk, ByteSpan msg, ByteSpan signature, crypto::MlDsa::Level level) {
    crypto::MlDsa dsa(level);
    crypto::Signature sig;
    sig.data.assign(signature.begin(), signature.end());
    auto res = dsa.verify(pk, msg, sig);
    if (!res) return err<bool>(res.error());
    return ok<bool>(res.value());
}

Result<Bytes> CryptoManager::sign_ecdsa_p256(const crypto::DsaPrivateKey& sk, ByteSpan msg) {
    crypto::EcdsaP256 dsa;
    auto sig_r = dsa.sign(sk, msg);
    if (!sig_r) return err<Bytes>(sig_r.error());
    return ok<Bytes>(sig_r.value().data);
}

Result<bool> CryptoManager::verify_ecdsa_p256(const crypto::DsaPublicKey& pk, ByteSpan msg, ByteSpan signature) {
    crypto::EcdsaP256 dsa;
    crypto::Signature sig;
    sig.data.assign(signature.begin(), signature.end());
    auto res = dsa.verify(pk, msg, sig);
    if (!res) return err<bool>(res.error());
    return ok<bool>(res.value());
}

Result<crypto::SharedSecret> CryptoManager::decapsulate_secret(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct) {
    crypto::HybridKem kem;
    return kem.decapsulate(sk, ct);
}

Result<crypto::EncapsulationResult> CryptoManager::encapsulate_secret(const crypto::KemPublicKey& pk) {
    crypto::HybridKem kem;
    return kem.encapsulate(pk);
}

Result<crypto::SharedSecret> CryptoManager::decapsulate_ml_kem(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct, crypto::MlKem::Level level) {
    crypto::MlKem kem(level);
    return kem.decapsulate(sk, ct);
}

Result<crypto::EncapsulationResult> CryptoManager::encapsulate_ml_kem(const crypto::KemPublicKey& pk, crypto::MlKem::Level level) {
    crypto::MlKem kem(level);
    return kem.encapsulate(pk);
}

Result<crypto::SharedSecret> CryptoManager::decapsulate_x25519(const crypto::KemPrivateKey& sk, const crypto::KemCiphertext& ct) {
    crypto::X25519Kem kem;
    return kem.decapsulate(sk, ct);
}

Result<crypto::EncapsulationResult> CryptoManager::encapsulate_x25519(const crypto::KemPublicKey& pk) {
    crypto::X25519Kem kem;
    return kem.encapsulate(pk);
}

Result<SecureBytes> CryptoManager::hkdf_sha256_extract_and_expand(ByteSpan salt, ByteSpan ikm, ByteSpan info, std::size_t out_len) {
    crypto::Hkdf hkdf(crypto::HkdfHash::Sha256);
    return hkdf.derive(salt, ikm, info, out_len);
}

Result<Bytes> CryptoManager::aes_gcm_encrypt(ByteSpan plaintext, ByteSpan key, ByteSpan iv, ByteSpan aad) {
    crypto::AesKeyLen len;
    if (key.size() == 16) {
        len = crypto::AesKeyLen::Aes128;
    } else if (key.size() == 32) {
        len = crypto::AesKeyLen::Aes256;
    } else {
        return err<Bytes>(ErrorCode::InvalidArgument, "Invalid AES-GCM key size");
    }
    crypto::AesGcm cipher(len);
    return cipher.encrypt(crypto::AeadKey::from_bytes(key), iv, plaintext, aad);
}

Result<Bytes> CryptoManager::aes_gcm_decrypt(ByteSpan ciphertext, ByteSpan key, ByteSpan iv, ByteSpan aad) {
    crypto::AesKeyLen len;
    if (key.size() == 16) {
        len = crypto::AesKeyLen::Aes128;
    } else if (key.size() == 32) {
        len = crypto::AesKeyLen::Aes256;
    } else {
        return err<Bytes>(ErrorCode::InvalidArgument, "Invalid AES-GCM key size");
    }
    crypto::AesGcm cipher(len);
    return cipher.decrypt(crypto::AeadKey::from_bytes(key), iv, ciphertext, aad);
}

Result<Bytes> CryptoManager::chacha20_poly1305_encrypt(ByteSpan plaintext, ByteSpan key, ByteSpan iv, ByteSpan aad) {
    if (key.size() != 32) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Invalid ChaCha20-Poly1305 key size");
    }
    crypto::ChaCha20Poly1305 cipher;
    return cipher.encrypt(crypto::AeadKey::from_bytes(key), iv, plaintext, aad);
}

Result<Bytes> CryptoManager::chacha20_poly1305_decrypt(ByteSpan ciphertext, ByteSpan key, ByteSpan iv, ByteSpan aad) {
    if (key.size() != 32) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Invalid ChaCha20-Poly1305 key size");
    }
    crypto::ChaCha20Poly1305 cipher;
    return cipher.decrypt(crypto::AeadKey::from_bytes(key), iv, ciphertext, aad);
}

Result<std::string> CryptoManager::export_dsa_private_key_to_pem(const crypto::DsaPrivateKey& sk, bool is_ecdsa) {
    std::string label = is_ecdsa ? "EC PRIVATE KEY" : "ML-DSA PRIVATE KEY";
    return ok<std::string>(to_pem(label, sk.data.span()));
}

Result<std::string> CryptoManager::export_dsa_public_key_to_pem(const crypto::DsaPublicKey& pk, bool is_ecdsa) {
    std::string label = is_ecdsa ? "PUBLIC KEY" : "ML-DSA PUBLIC KEY";
    return ok<std::string>(to_pem(label, pk.data));
}

Result<crypto::DsaKeyPair> CryptoManager::import_dsa_keypair_from_pem(const std::string& private_pem, const std::string& public_pem, bool is_ecdsa) {
    std::string priv_label = is_ecdsa ? "EC PRIVATE KEY" : "ML-DSA PRIVATE KEY";
    std::string pub_label = is_ecdsa ? "PUBLIC KEY" : "ML-DSA PUBLIC KEY";

    auto priv_r = from_pem(priv_label, private_pem);
    if (!priv_r) return err<crypto::DsaKeyPair>(priv_r.error());

    auto pub_r = from_pem(pub_label, public_pem);
    if (!pub_r) return err<crypto::DsaKeyPair>(pub_r.error());

    crypto::DsaKeyPair kp;
    kp.private_key.data = SecureBytes(std::move(priv_r.value()));
    kp.public_key.data = std::move(pub_r.value());
    return ok<crypto::DsaKeyPair>(std::move(kp));
}

void CryptoManager::set_static_dsa_keypair(crypto::DsaKeyPair keypair) {
    std::lock_guard<std::mutex> lock(mutex_);
    static_dsa_keypair_ = std::move(keypair);
}

void CryptoManager::clean_sensitive_memory(MutableByteSpan span) noexcept {
    secure_zero(span);
}

} // namespace uav_pqc::app
