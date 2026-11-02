// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file hkdf.cpp
 * @brief HKDF (RFC 5869) via OpenSSL 3 EVP_KDF.
 */

#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"

#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

namespace uav_pqc::crypto {

namespace {

struct EvpKdfDeleter    { void operator()(EVP_KDF* p)     const noexcept { EVP_KDF_free(p); } };
struct EvpKdfCtxDeleter { void operator()(EVP_KDF_CTX* p) const noexcept { EVP_KDF_CTX_free(p); } };

using EvpKdfPtr    = std::unique_ptr<EVP_KDF,     EvpKdfDeleter>;
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

/// Maps our HkdfHash enum to the OpenSSL digest name string.
const char* digest_name(HkdfHash hash) noexcept {
    switch (hash) {
        case HkdfHash::Sha256: return "SHA256";
        case HkdfHash::Sha384: return "SHA384";
        case HkdfHash::Sha512: return "SHA512";
    }
    return "SHA256";
}

/// Returns the hash output byte length.
std::size_t digest_size(HkdfHash hash) noexcept {
    switch (hash) {
        case HkdfHash::Sha256: return 32;
        case HkdfHash::Sha384: return 48;
        case HkdfHash::Sha512: return 64;
    }
    return 32;
}

} // anonymous namespace

// ── Constructor / Destructor / Move ───────────────────────────────────────────

Hkdf::Hkdf(HkdfHash hash) : hash_(hash) {}
Hkdf::~Hkdf() = default;
Hkdf::Hkdf(Hkdf&&) noexcept = default;
Hkdf& Hkdf::operator=(Hkdf&&) noexcept = default;

// ── Metadata ──────────────────────────────────────────────────────────────────

std::size_t      Hkdf::hash_output_size() const noexcept { return digest_size(hash_); }
std::string_view Hkdf::algorithm_id()     const noexcept {
    switch (hash_) {
        case HkdfHash::Sha256: return "HKDF-SHA256";
        case HkdfHash::Sha384: return "HKDF-SHA384";
        case HkdfHash::Sha512: return "HKDF-SHA512";
    }
    return "HKDF-SHA256";
}

// ── Internal helper: run the OpenSSL 3 EVP_KDF ────────────────────────────────

static Result<SecureBytes> run_hkdf(HkdfHash hash,
                                     int mode,
                                     ByteSpan salt,
                                     ByteSpan ikm,
                                     ByteSpan info,
                                     std::size_t out_len) {
    EvpKdfPtr kdf{EVP_KDF_fetch(nullptr, "HKDF", nullptr)};
    if (!kdf) {
        return err<SecureBytes>(ErrorCode::HkdfFailed, "EVP_KDF_fetch(HKDF) failed");
    }
    EvpKdfCtxPtr ctx{EVP_KDF_CTX_new(kdf.get())};
    if (!ctx) {
        return err<SecureBytes>(ErrorCode::HkdfFailed, "EVP_KDF_CTX_new failed");
    }

    // Build parameter list
    OSSL_PARAM params[6];
    int n = 0;

    params[n++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest_name(hash)), 0);
    params[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);

    if (!ikm.empty()) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            const_cast<void*>(static_cast<const void*>(ikm.data())), ikm.size());
    }
    if (!salt.empty()) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            const_cast<void*>(static_cast<const void*>(salt.data())), salt.size());
    }
    if (!info.empty()) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            const_cast<void*>(static_cast<const void*>(info.data())), info.size());
    }
    params[n] = OSSL_PARAM_END;

    SecureBytes out(out_len);
    if (EVP_KDF_derive(ctx.get(),
            reinterpret_cast<unsigned char*>(out.data()), out.size(),
            params) <= 0) {
        return err<SecureBytes>(ErrorCode::HkdfFailed, "EVP_KDF_derive(HKDF) failed");
    }
    return ok<SecureBytes>(std::move(out));
}

// ── Public API ────────────────────────────────────────────────────────────────

Result<SecureBytes> Hkdf::extract(ByteSpan salt, ByteSpan ikm) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Hkdf);
    // EVP_KDF_HKDF_MODE_EXTRACT_ONLY = 1
    return run_hkdf(hash_, EVP_KDF_HKDF_MODE_EXTRACT_ONLY, salt, ikm, {}, digest_size(hash_));
}

Result<SecureBytes> Hkdf::expand(ByteSpan prk, ByteSpan info, std::size_t length) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Hkdf);
    // EVP_KDF_HKDF_MODE_EXPAND_ONLY = 2
    return run_hkdf(hash_, EVP_KDF_HKDF_MODE_EXPAND_ONLY, {}, prk, info, length);
}

Result<SecureBytes> Hkdf::derive(ByteSpan salt, ByteSpan ikm,
                                  ByteSpan info, std::size_t length) const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Hkdf);
    // EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND = 0
    return run_hkdf(hash_, EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND, salt, ikm, info, length);
}

} // namespace uav_pqc::crypto
