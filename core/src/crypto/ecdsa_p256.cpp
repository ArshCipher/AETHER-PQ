// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file ecdsa_p256.cpp
 * @brief ECDSA over NIST P-256 with SHA-256 via OpenSSL 3 EVP.
 */

#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>

namespace uav_pqc::crypto {

namespace {

struct EvpPkeyDeleter    { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } };
struct EvpMdCtxDeleter   { void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); } };

using EvpPkeyPtr    = std::unique_ptr<EVP_PKEY,    EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtxPtr   = std::unique_ptr<EVP_MD_CTX,   EvpMdCtxDeleter>;

/// Generate an EC key on NID_X9_62_prime256v1 (P-256).
Result<EvpPkeyPtr> generate_p256_key() {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        return err<EvpPkeyPtr>(ErrorCode::KeyGenerationFailed,
                               "EVP_PKEY keygen init for EC failed");
    }
    // Set the curve to P-256
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) {
        return err<EvpPkeyPtr>(ErrorCode::KeyGenerationFailed,
                               "EVP_PKEY_CTX_set_ec_paramgen_curve_nid(P-256) failed");
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_generate(ctx.get(), &raw) <= 0 || !raw) {
        return err<EvpPkeyPtr>(ErrorCode::KeyGenerationFailed,
                               "EVP_PKEY_generate(EC P-256) failed");
    }
    return ok<EvpPkeyPtr>(EvpPkeyPtr{raw});
}

} // anonymous namespace

// ── Metadata ──────────────────────────────────────────────────────────────────

std::string_view EcdsaP256::algorithm_id()       const noexcept { return "ECDSA-P256"; }
std::size_t      EcdsaP256::public_key_size()    const noexcept { return 65; }  // uncompressed
std::size_t      EcdsaP256::private_key_size()   const noexcept { return 32; }
std::size_t      EcdsaP256::max_signature_size() const noexcept { return 72; }  // max DER ECDSA sig

// ── generate_keypair ──────────────────────────────────────────────────────────

Result<DsaKeyPair> EcdsaP256::generate_keypair() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Ecdsa);
    auto key_result = generate_p256_key();
    if (!key_result) return err<DsaKeyPair>(key_result.error());
    auto& pkey = key_result.value();

    DsaKeyPair kp;

    // Export uncompressed SEC1 public key (65 bytes: 0x04 || Qx || Qy)
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey.get());
    if (!ec) {
        return err<DsaKeyPair>(ErrorCode::KeyGenerationFailed,
                               "Failed to extract EC_KEY from EVP_PKEY");
    }
    EC_KEY_set_conv_form(ec, POINT_CONVERSION_UNCOMPRESSED);
    unsigned char* buf = nullptr;
    int len = i2o_ECPublicKey(ec, &buf);
    if (len != 65 || !buf) {
        if (buf) OPENSSL_free(buf);
        EC_KEY_free(ec);
        return err<DsaKeyPair>(ErrorCode::KeyGenerationFailed,
                               "Failed to export uncompressed P-256 public key");
    }
    kp.public_key.data.resize(65);
    std::memcpy(kp.public_key.data.data(), buf, 65);
    OPENSSL_free(buf);
    EC_KEY_free(ec);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

    // Export raw private scalar (32 bytes)
    BIGNUM* bn = nullptr;
    if (EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &bn) <= 0) {
        return err<DsaKeyPair>(ErrorCode::KeyGenerationFailed,
                               "Failed to export P-256 private key");
    }
    kp.private_key.data.resize(32);
    BN_bn2binpad(bn, reinterpret_cast<unsigned char*>(kp.private_key.data.data()), 32);
    BN_free(bn);
    return ok<DsaKeyPair>(std::move(kp));
}

// ── sign ──────────────────────────────────────────────────────────────────────

Result<Signature> EcdsaP256::sign(const DsaPrivateKey& sk, ByteSpan message) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Ecdsa);
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        return err<Signature>(ErrorCode::SigningFailed, "OSSL_PARAM_BLD_new failed");
    }
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    
    BIGNUM* bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(sk.data.data()), sk.data.size(), nullptr);
    if (!bn) {
        OSSL_PARAM_BLD_free(bld);
        return err<Signature>(ErrorCode::SigningFailed, "BN_bin2bn failed");
    }
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn);
    
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    BN_free(bn);
    OSSL_PARAM_BLD_free(bld);

    if (!params) {
        return err<Signature>(ErrorCode::SigningFailed, "OSSL_PARAM_BLD_to_param failed");
    }

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* raw_key = nullptr;
    if (kctx) {
        EVP_PKEY_fromdata_init(kctx);
        EVP_PKEY_fromdata(kctx, &raw_key, EVP_PKEY_KEYPAIR, params);
        EVP_PKEY_CTX_free(kctx);
    }
    OSSL_PARAM_free(params);

    if (!raw_key) {
        return err<Signature>(ErrorCode::SigningFailed,
                              "Failed to load P-256 private key for signing");
    }
    EvpPkeyPtr pkey{raw_key};

    EvpMdCtxPtr md_ctx{EVP_MD_CTX_new()};
    if (!md_ctx) {
        return err<Signature>(ErrorCode::SigningFailed, "EVP_MD_CTX_new failed");
    }
    if (EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0) {
        return err<Signature>(ErrorCode::SigningFailed, "EVP_DigestSignInit(P-256) failed");
    }

    // Determine signature size
    std::size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len,
            reinterpret_cast<const unsigned char*>(message.data()), message.size()) <= 0) {
        return err<Signature>(ErrorCode::SigningFailed, "EVP_DigestSign size query failed");
    }

    Signature sig;
    sig.data.resize(sig_len);
    if (EVP_DigestSign(md_ctx.get(),
            reinterpret_cast<unsigned char*>(sig.data.data()), &sig_len,
            reinterpret_cast<const unsigned char*>(message.data()), message.size()) <= 0) {
        return err<Signature>(ErrorCode::SigningFailed, "EVP_DigestSign(P-256) failed");
    }
    sig.data.resize(sig_len);
    return ok<Signature>(std::move(sig));
}

// ── verify ────────────────────────────────────────────────────────────────────

Result<bool> EcdsaP256::verify(const DsaPublicKey& pk, ByteSpan message,
                                const Signature& signature) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Ecdsa);
    // Load public key from uncompressed SEC1 bytes
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
        pk.data.data(), pk.data.size());
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* raw_key  = nullptr;
    EVP_PKEY_fromdata_init(kctx);
    EVP_PKEY_fromdata(kctx, &raw_key, EVP_PKEY_PUBLIC_KEY, params);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(kctx);

    if (!raw_key) {
        return err<bool>(ErrorCode::InvalidArgument,
                         "Failed to load P-256 public key for verification");
    }
    EvpPkeyPtr pkey{raw_key};

    EvpMdCtxPtr md_ctx{EVP_MD_CTX_new()};
    if (!md_ctx || EVP_DigestVerifyInit(md_ctx.get(), nullptr, EVP_sha256(),
                                         nullptr, pkey.get()) <= 0) {
        return err<bool>(ErrorCode::InternalError, "EVP_DigestVerifyInit failed");
    }

    const int rc = EVP_DigestVerify(
        md_ctx.get(),
        reinterpret_cast<const unsigned char*>(signature.data.data()),
        signature.data.size(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size());

    if (rc == 1) {
        return ok<bool>(true);
    }
    UAV_PQC_LOG_WARN("crypto.ecdsa_p256", "Signature verification failed");
    return err<bool>(ErrorCode::VerificationFailed, "ECDSA-P256 signature verification failed");
}

// ── DER import / export ───────────────────────────────────────────────────────

Result<DsaPublicKey> EcdsaP256::import_public_key_from_der(ByteSpan der) const {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    EVP_PKEY* raw = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    if (!raw) {
        return err<DsaPublicKey>(ErrorCode::InvalidArgument,
                                  "d2i_PUBKEY failed: invalid DER SPKI");
    }
    EvpPkeyPtr pkey{raw};

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey.get());
    if (!ec) {
        return err<DsaPublicKey>(ErrorCode::InvalidArgument,
                                  "Failed to extract EC_KEY from DER key");
    }
    EC_KEY_set_conv_form(ec, POINT_CONVERSION_UNCOMPRESSED);
    unsigned char* buf = nullptr;
    int len = i2o_ECPublicKey(ec, &buf);
    if (len != 65 || !buf) {
        if (buf) OPENSSL_free(buf);
        EC_KEY_free(ec);
        return err<DsaPublicKey>(ErrorCode::InvalidArgument,
                                  "Failed to extract uncompressed P-256 point from DER key");
    }
    DsaPublicKey pk;
    pk.data.resize(65);
    std::memcpy(pk.data.data(), buf, 65);
    OPENSSL_free(buf);
    EC_KEY_free(ec);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
    return ok<DsaPublicKey>(std::move(pk));
}

Result<Bytes> EcdsaP256::export_public_key_to_der(const DsaPublicKey& pk) const {
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
        pk.data.data(), pk.data.size());
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* raw_key  = nullptr;
    EVP_PKEY_fromdata_init(kctx);
    EVP_PKEY_fromdata(kctx, &raw_key, EVP_PKEY_PUBLIC_KEY, params);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(kctx);

    if (!raw_key) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Failed to load P-256 key for DER export");
    }
    EvpPkeyPtr pkey{raw_key};

    unsigned char* der_buf = nullptr;
    const int der_len = i2d_PUBKEY(pkey.get(), &der_buf);
    if (der_len <= 0 || !der_buf) {
        return err<Bytes>(ErrorCode::InternalError, "i2d_PUBKEY failed");
    }
    Bytes result(reinterpret_cast<std::byte*>(der_buf),
                 reinterpret_cast<std::byte*>(der_buf) + der_len);
    OPENSSL_free(der_buf);
    return ok<Bytes>(std::move(result));
}

} // namespace uav_pqc::crypto
