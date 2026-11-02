// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file x25519.cpp
 * @brief X25519 Diffie-Hellman wrapped as a KEM via OpenSSL 3 EVP.
 *
 * The "encapsulate" operation generates an ephemeral key pair and computes
 * the DH shared secret with the recipient's static public key.  The
 * "ciphertext" is the encapsulator's ephemeral public key (32 bytes),
 * sent to the decapsulator so it can compute the same shared secret.
 */

#include "uav_pqc/crypto/x25519.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <array>
#include <cstring>

namespace uav_pqc::crypto {

namespace {

// RAII wrappers for OpenSSL EVP types
struct EvpPkeyDeleter  { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } };

using EvpPkeyPtr    = std::unique_ptr<EVP_PKEY,    EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

/// Generate a fresh X25519 key pair using OpenSSL 3 EVP.
Result<std::pair<EvpPkeyPtr, Bytes>> generate_x25519_keypair() {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "X25519", nullptr)};
    if (!ctx) {
        return err<std::pair<EvpPkeyPtr, Bytes>>(ErrorCode::KeyGenerationFailed,
                                                  "EVP_PKEY_CTX_new_from_name(X25519) failed");
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        return err<std::pair<EvpPkeyPtr, Bytes>>(ErrorCode::KeyGenerationFailed,
                                                  "EVP_PKEY_keygen_init failed");
    }
    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_generate(ctx.get(), &raw_key) <= 0 || !raw_key) {
        return err<std::pair<EvpPkeyPtr, Bytes>>(ErrorCode::KeyGenerationFailed,
                                                  "EVP_PKEY_generate(X25519) failed");
    }
    EvpPkeyPtr pkey{raw_key};

    // Extract raw 32-byte public key
    std::size_t pub_len = 32;
    Bytes pub_bytes(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey.get(),
            reinterpret_cast<unsigned char*>(pub_bytes.data()), &pub_len) <= 0) {
        return err<std::pair<EvpPkeyPtr, Bytes>>(ErrorCode::KeyGenerationFailed,
                                                  "EVP_PKEY_get_raw_public_key failed");
    }
    pub_bytes.resize(pub_len);
    return ok(std::make_pair(std::move(pkey), std::move(pub_bytes)));
}

/// Load an EVP_PKEY from raw 32-byte X25519 public key bytes.
Result<EvpPkeyPtr> load_x25519_public_key(ByteSpan raw_pub) {
    if (raw_pub.size() != 32) {
        return err<EvpPkeyPtr>(ErrorCode::InvalidArgument,
                               "X25519 public key must be exactly 32 bytes");
    }
    EVP_PKEY* p = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char*>(raw_pub.data()), raw_pub.size());
    if (!p) {
        return err<EvpPkeyPtr>(ErrorCode::InvalidArgument,
                               "EVP_PKEY_new_raw_public_key(X25519) failed");
    }
    return ok<EvpPkeyPtr>(EvpPkeyPtr{p});
}

/// Perform the actual X25519 DH computation using two EVP_PKEY objects.
Result<SharedSecret> ecdh_compute(EVP_PKEY* local_key, EVP_PKEY* peer_pub) {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new(local_key, nullptr)};
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0) {
        return err<SharedSecret>(ErrorCode::KeyDerivationFailed,
                                  "EVP_PKEY_derive_init failed");
    }
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer_pub) <= 0) {
        return err<SharedSecret>(ErrorCode::KeyDerivationFailed,
                                  "EVP_PKEY_derive_set_peer failed");
    }
    std::size_t secret_len = 32;
    SharedSecret ss;
    ss.data.resize(secret_len);
    if (EVP_PKEY_derive(ctx.get(),
            reinterpret_cast<unsigned char*>(ss.data.data()), &secret_len) <= 0) {
        return err<SharedSecret>(ErrorCode::KeyDerivationFailed,
                                  "EVP_PKEY_derive(X25519) failed");
    }
    ss.data.resize(secret_len);
    return ok<SharedSecret>(std::move(ss));
}

} // anonymous namespace

// ── Metadata ──────────────────────────────────────────────────────────────────

std::string_view X25519Kem::algorithm_id()       const noexcept { return "X25519-KEM"; }
std::size_t      X25519Kem::public_key_size()    const noexcept { return 32; }
std::size_t      X25519Kem::private_key_size()   const noexcept { return 32; }
std::size_t      X25519Kem::ciphertext_size()    const noexcept { return 32; } // ephemeral pubkey
std::size_t      X25519Kem::shared_secret_size() const noexcept { return 32; }

// ── generate_keypair ──────────────────────────────────────────────────────────

Result<KemKeyPair> X25519Kem::generate_keypair() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::X25519);
    auto pair_result = generate_x25519_keypair();
    if (!pair_result) return err<KemKeyPair>(pair_result.error());

    auto& [pkey, pub_bytes] = pair_result.value();

    // Extract raw 32-byte private key
    std::size_t priv_len = 32;
    SecureBytes priv_bytes(priv_len);
    if (EVP_PKEY_get_raw_private_key(pkey.get(),
            reinterpret_cast<unsigned char*>(priv_bytes.data()), &priv_len) <= 0) {
        return err<KemKeyPair>(ErrorCode::KeyGenerationFailed,
                               "EVP_PKEY_get_raw_private_key(X25519) failed");
    }

    KemKeyPair kp;
    kp.public_key.data  = std::move(pub_bytes);
    kp.private_key.data = std::move(priv_bytes);
    return ok<KemKeyPair>(std::move(kp));
}

// ── encapsulate ───────────────────────────────────────────────────────────────

Result<EncapsulationResult> X25519Kem::encapsulate(const KemPublicKey& recipient_pk) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::X25519);
    // Load recipient static public key
    auto peer_result = load_x25519_public_key(recipient_pk.span());
    if (!peer_result) return err<EncapsulationResult>(peer_result.error());

    // Generate ephemeral key pair
    auto eph_result = generate_x25519_keypair();
    if (!eph_result) return err<EncapsulationResult>(eph_result.error());
    auto& [eph_pkey, eph_pub] = eph_result.value();

    // Compute DH shared secret: ephemeral_private × recipient_static_public
    auto ss_result = ecdh_compute(eph_pkey.get(), peer_result.value().get());
    if (!ss_result) return err<EncapsulationResult>(ss_result.error());

    EncapsulationResult result;
    result.ciphertext.data  = std::move(eph_pub);       // send to recipient
    result.shared_secret    = std::move(ss_result.value());
    return ok<EncapsulationResult>(std::move(result));
}

// ── decapsulate ───────────────────────────────────────────────────────────────

Result<SharedSecret> X25519Kem::decapsulate(const KemPrivateKey& sk,
                                              const KemCiphertext& ct) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::X25519);
    if (sk.data.size() != 32) {
        return err<SharedSecret>(ErrorCode::InvalidArgument,
                                  "X25519 decapsulate: private key must be 32 bytes");
    }
    if (ct.data.size() != 32) {
        return err<SharedSecret>(ErrorCode::InvalidArgument,
                                  "X25519 decapsulate: ciphertext (ephemeral pk) must be 32 bytes");
    }

    // Load our static private key
    EVP_PKEY* local_raw = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char*>(sk.data.data()), sk.data.size());
    if (!local_raw) {
        return err<SharedSecret>(ErrorCode::DecapsulationFailed,
                                  "EVP_PKEY_new_raw_private_key(X25519) failed");
    }
    EvpPkeyPtr local_pkey{local_raw};

    // Load sender's ephemeral public key from ciphertext
    auto peer_result = load_x25519_public_key(ct.span());
    if (!peer_result) return err<SharedSecret>(peer_result.error());

    // Compute DH: our_static_private × sender_ephemeral_public
    return ecdh_compute(local_pkey.get(), peer_result.value().get());
}

// ── raw_dh ────────────────────────────────────────────────────────────────────

Result<SharedSecret> X25519Kem::raw_dh(const KemPrivateKey& private_key,
                                         const KemPublicKey&  peer_public) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::X25519);
    EVP_PKEY* local_raw = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char*>(private_key.data.data()),
        private_key.data.size());
    if (!local_raw) {
        return err<SharedSecret>(ErrorCode::KeyDerivationFailed,
                                  "raw_dh: EVP_PKEY_new_raw_private_key failed");
    }
    EvpPkeyPtr local_pkey{local_raw};

    auto peer_result = load_x25519_public_key(peer_public.span());
    if (!peer_result) return err<SharedSecret>(peer_result.error());

    return ecdh_compute(local_pkey.get(), peer_result.value().get());
}

Result<KemKeyPair> X25519Kem::generate_keypair_deterministic(ByteSpan seed) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::X25519);
    Hkdf hkdf(HkdfHash::Sha256);
    auto derived_r = hkdf.derive({}, seed, bytes_from_sv("x25519 keypair seed"), 32);
    if (!derived_r) return err<KemKeyPair>(derived_r.error());

    SecureBytes priv_bytes = std::move(derived_r.value());

    EVP_PKEY* raw_pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char*>(priv_bytes.data()), 32);
    if (!raw_pkey) {
        return err<KemKeyPair>(ErrorCode::KeyGenerationFailed,
                               "EVP_PKEY_new_raw_private_key failed");
    }
    EvpPkeyPtr pkey{raw_pkey};

    std::size_t pub_len = 32;
    Bytes pub_bytes(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey.get(),
            reinterpret_cast<unsigned char*>(pub_bytes.data()), &pub_len) <= 0) {
        return err<KemKeyPair>(ErrorCode::KeyGenerationFailed,
                               "EVP_PKEY_get_raw_public_key failed");
    }
    pub_bytes.resize(pub_len);

    KemKeyPair kp;
    kp.public_key.data  = std::move(pub_bytes);
    kp.private_key.data = std::move(priv_bytes);
    return ok<KemKeyPair>(std::move(kp));
}

} // namespace uav_pqc::crypto
