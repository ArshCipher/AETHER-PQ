// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file hybrid_kem.cpp
 * @brief Hybrid ML-KEM-768 + X25519 KEM implementation.
 *
 * Wire format (ciphertext):
 *   [0..1087]  : ML-KEM-768 ciphertext (1088 bytes)
 *   [1088..1119]: X25519 ephemeral public key (32 bytes)
 *
 * Wire format (public key):
 *   [0..1183]  : ML-KEM-768 public key (1184 bytes)
 *   [1184..1215]: X25519 static public key (32 bytes)
 *
 * Shared secret derivation:
 *   combined_ikm = mlkem_ss || x25519_ss   (64 bytes)
 *   session_key  = HKDF-SHA256(salt=∅, ikm=combined_ikm, info=context_, length=32)
 */

#include "uav_pqc/crypto/hybrid_kem.hpp"
#include "uav_pqc/common/logging.hpp"

#include <algorithm>
#include <stdexcept>

namespace uav_pqc::crypto {

// ── Constructor ───────────────────────────────────────────────────────────────

HybridKem::HybridKem(std::string_view context)
    : mlkem_(MlKem::Level::Kem768),
      x25519_(),
      hkdf_(HkdfHash::Sha256),
      context_(context) {}

// ── Metadata ──────────────────────────────────────────────────────────────────

std::string_view HybridKem::algorithm_id()       const noexcept { return "Hybrid-ML-KEM-768-X25519"; }
std::size_t HybridKem::mlkem_public_key_size()   const noexcept { return mlkem_.public_key_size(); }
std::size_t HybridKem::x25519_public_key_size()  const noexcept { return x25519_.public_key_size(); }
std::size_t HybridKem::public_key_size()    const noexcept { return mlkem_.public_key_size() + x25519_.public_key_size(); }
std::size_t HybridKem::private_key_size()   const noexcept { return mlkem_.private_key_size() + x25519_.private_key_size(); }
std::size_t HybridKem::ciphertext_size()    const noexcept { return mlkem_.ciphertext_size() + x25519_.ciphertext_size(); }
std::size_t HybridKem::shared_secret_size() const noexcept { return 32; } // HKDF output

// ── generate_keypair ──────────────────────────────────────────────────────────

Result<KemKeyPair> HybridKem::generate_keypair() const {
    auto mlkem_kp_r = mlkem_.generate_keypair();
    if (!mlkem_kp_r) return err<KemKeyPair>(mlkem_kp_r.error());

    auto x25519_kp_r = x25519_.generate_keypair();
    if (!x25519_kp_r) return err<KemKeyPair>(x25519_kp_r.error());

    auto& mlkem_kp   = mlkem_kp_r.value();
    auto& x25519_kp  = x25519_kp_r.value();

    KemKeyPair kp;

    // Public key = ML-KEM-768 pk || X25519 pk
    kp.public_key.data.reserve(public_key_size());
    kp.public_key.data.insert(kp.public_key.data.end(),
        mlkem_kp.public_key.data.begin(), mlkem_kp.public_key.data.end());
    kp.public_key.data.insert(kp.public_key.data.end(),
        x25519_kp.public_key.data.begin(), x25519_kp.public_key.data.end());

    // Private key = ML-KEM-768 sk || X25519 sk
    kp.private_key.data.resize(private_key_size());
    {
        MutableByteSpan dst = kp.private_key.data.span();
        std::copy(mlkem_kp.private_key.data.data(),
                  mlkem_kp.private_key.data.data() + mlkem_kp.private_key.data.size(),
                  dst.data());
        std::copy(x25519_kp.private_key.data.data(),
                  x25519_kp.private_key.data.data() + x25519_kp.private_key.data.size(),
                  dst.data() + mlkem_kp.private_key.data.size());
    }

    UAV_PQC_LOG_TRACE("crypto.hybrid_kem", "generate_keypair: pk={} sk={}",
                      kp.public_key.size(), kp.private_key.size());
    return ok<KemKeyPair>(std::move(kp));
}

// ── encapsulate ───────────────────────────────────────────────────────────────

Result<EncapsulationResult> HybridKem::encapsulate(const KemPublicKey& pk) const {
    if (pk.data.size() != public_key_size()) {
        return err<EncapsulationResult>(ErrorCode::InvalidArgument,
            "HybridKem encapsulate: public key size incorrect");
    }

    // Split composite public key
    KemPublicKey mlkem_pk;
    mlkem_pk.data = Bytes(pk.data.begin(), pk.data.begin() + mlkem_.public_key_size());

    KemPublicKey x25519_pk;
    x25519_pk.data = Bytes(pk.data.begin() + mlkem_.public_key_size(), pk.data.end());

    // Run both KEMs
    auto mlkem_r = mlkem_.encapsulate(mlkem_pk);
    if (!mlkem_r) return err<EncapsulationResult>(mlkem_r.error());

    auto x25519_r = x25519_.encapsulate(x25519_pk);
    if (!x25519_r) return err<EncapsulationResult>(x25519_r.error());

    // Combine: combined_ikm = mlkem_ss (32) || x25519_ss (32)
    const std::size_t combined_len =
        mlkem_r.value().shared_secret.size() + x25519_r.value().shared_secret.size();
    Bytes combined_ikm(combined_len);
    {
        auto* p = combined_ikm.data();
        std::copy(mlkem_r.value().shared_secret.data.data(),
                  mlkem_r.value().shared_secret.data.data() + mlkem_r.value().shared_secret.size(),
                  p);
        p += mlkem_r.value().shared_secret.size();
        std::copy(x25519_r.value().shared_secret.data.data(),
                  x25519_r.value().shared_secret.data.data() + x25519_r.value().shared_secret.size(),
                  p);
    }

    // HKDF to derive final 32-byte shared secret
    const Bytes context_bytes(reinterpret_cast<const std::byte*>(context_.data()),
                               reinterpret_cast<const std::byte*>(context_.data()) + context_.size());
    auto hkdf_r = hkdf_.derive(
        ByteSpan{}, ByteSpan{combined_ikm.data(), combined_ikm.size()},
        ByteSpan{context_bytes.data(), context_bytes.size()}, 32);
    if (!hkdf_r) return err<EncapsulationResult>(hkdf_r.error());

    // Assemble composite ciphertext: mlkem_ct || x25519_ct
    EncapsulationResult result;
    result.ciphertext.data.reserve(ciphertext_size());
    result.ciphertext.data.insert(result.ciphertext.data.end(),
        mlkem_r.value().ciphertext.data.begin(), mlkem_r.value().ciphertext.data.end());
    result.ciphertext.data.insert(result.ciphertext.data.end(),
        x25519_r.value().ciphertext.data.begin(), x25519_r.value().ciphertext.data.end());

    result.shared_secret = SharedSecret{std::move(hkdf_r.value())};
    return ok<EncapsulationResult>(std::move(result));
}

// ── decapsulate ───────────────────────────────────────────────────────────────

Result<SharedSecret> HybridKem::decapsulate(const KemPrivateKey& sk,
                                              const KemCiphertext& ct) const {
    if (sk.data.size() != private_key_size()) {
        return err<SharedSecret>(ErrorCode::InvalidArgument,
            "HybridKem decapsulate: private key size incorrect");
    }
    if (ct.data.size() != ciphertext_size()) {
        return err<SharedSecret>(ErrorCode::InvalidArgument,
            "HybridKem decapsulate: ciphertext size incorrect");
    }

    // Split private key
    KemPrivateKey mlkem_sk, x25519_sk;
    mlkem_sk.data.resize(mlkem_.private_key_size());
    std::copy(sk.data.data(), sk.data.data() + mlkem_.private_key_size(),
              mlkem_sk.data.data());

    x25519_sk.data.resize(x25519_.private_key_size());
    std::copy(sk.data.data() + mlkem_.private_key_size(),
              sk.data.data() + sk.data.size(), x25519_sk.data.data());

    // Split ciphertext
    KemCiphertext mlkem_ct, x25519_ct;
    mlkem_ct.data = Bytes(ct.data.begin(), ct.data.begin() + mlkem_.ciphertext_size());
    x25519_ct.data = Bytes(ct.data.begin() + mlkem_.ciphertext_size(), ct.data.end());

    // Decapsulate both
    auto mlkem_ss_r = mlkem_.decapsulate(mlkem_sk, mlkem_ct);
    if (!mlkem_ss_r) return err<SharedSecret>(mlkem_ss_r.error());

    auto x25519_ss_r = x25519_.decapsulate(x25519_sk, x25519_ct);
    if (!x25519_ss_r) return err<SharedSecret>(x25519_ss_r.error());

    // Combine shared secrets via HKDF
    const std::size_t combined_len =
        mlkem_ss_r.value().size() + x25519_ss_r.value().size();
    Bytes combined(combined_len);
    {
        auto* p = combined.data();
        std::copy(mlkem_ss_r.value().data.data(),
                  mlkem_ss_r.value().data.data() + mlkem_ss_r.value().size(), p);
        p += mlkem_ss_r.value().size();
        std::copy(x25519_ss_r.value().data.data(),
                  x25519_ss_r.value().data.data() + x25519_ss_r.value().size(), p);
    }

    const Bytes context_bytes(reinterpret_cast<const std::byte*>(context_.data()),
                               reinterpret_cast<const std::byte*>(context_.data()) + context_.size());
    auto hkdf_r = hkdf_.derive(
        ByteSpan{}, ByteSpan{combined.data(), combined.size()},
        ByteSpan{context_bytes.data(), context_bytes.size()}, 32);
    if (!hkdf_r) return err<SharedSecret>(hkdf_r.error());

    return ok<SharedSecret>(SharedSecret{std::move(hkdf_r.value())});
}

Result<KemKeyPair> HybridKem::generate_keypair_deterministic(ByteSpan seed) const {
    auto mlkem_seed_r = hkdf_.derive(
        {},
        seed,
        bytes_from_sv("hybrid-kem deterministic ml-kem seed"),
        64
    );
    if (!mlkem_seed_r) return err<KemKeyPair>(mlkem_seed_r.error());

    auto x25519_seed_r = hkdf_.derive(
        {},
        seed,
        bytes_from_sv("hybrid-kem deterministic x25519 seed"),
        32
    );
    if (!x25519_seed_r) return err<KemKeyPair>(x25519_seed_r.error());

    auto mlkem_kp_r = mlkem_.generate_keypair_deterministic(mlkem_seed_r.value().span());
    if (!mlkem_kp_r) return err<KemKeyPair>(mlkem_kp_r.error());

    auto x25519_kp_r = x25519_.generate_keypair_deterministic(x25519_seed_r.value().span());
    if (!x25519_kp_r) return err<KemKeyPair>(x25519_kp_r.error());

    auto& mlkem_kp   = mlkem_kp_r.value();
    auto& x25519_kp  = x25519_kp_r.value();

    KemKeyPair kp;

    kp.public_key.data.reserve(public_key_size());
    kp.public_key.data.insert(kp.public_key.data.end(),
        mlkem_kp.public_key.data.begin(), mlkem_kp.public_key.data.end());
    kp.public_key.data.insert(kp.public_key.data.end(),
        x25519_kp.public_key.data.begin(), x25519_kp.public_key.data.end());

    kp.private_key.data.resize(private_key_size());
    {
        MutableByteSpan dst = kp.private_key.data.span();
        std::copy(mlkem_kp.private_key.data.data(),
                  mlkem_kp.private_key.data.data() + mlkem_kp.private_key.data.size(),
                  dst.data());
        std::copy(x25519_kp.private_key.data.data(),
                  x25519_kp.private_key.data.data() + x25519_kp.private_key.data.size(),
                  dst.data() + mlkem_kp.private_key.data.size());
    }

    return ok<KemKeyPair>(std::move(kp));
}

} // namespace uav_pqc::crypto
