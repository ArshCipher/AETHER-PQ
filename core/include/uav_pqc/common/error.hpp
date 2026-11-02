// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file error.hpp
 * @brief Error codes and Result<T> type for the uav_pqc library.
 *
 * The library never throws exceptions in its core path so that it can be
 * linked into firmware builds where exception handling is disabled.  All
 * fallible operations return a Result<T> (success) or Result<void> alias.
 *
 * The Result<T> interface mirrors std::expected<T, Error> from C++23 so that
 * the codebase can be trivially migrated once C++23 is widely available on
 * all target toolchains (Raspberry Pi, Yocto, STM32 arm-none-eabi).
 */

#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <cstdio>
#include <cstdlib>
#include <optional>

namespace uav_pqc {

// ─────────────────────────────────────────────────────────────────────────────
// Error codes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Canonical error code enumeration.
 *
 * Values are fixed (not underlying-type dependent) so they can safely be
 * serialised in protocol messages and compared across compilation units.
 */
enum class ErrorCode : std::uint32_t {
    // Success sentinel — only used when constructing an Error at the call site
    // in generic contexts; normal success is encoded by Result<T>::ok().
    Ok = 0,

    // ── Argument / usage errors ──────────────────────────────────────────────
    InvalidArgument     = 1000, ///< Caller passed a null, zero-size, or OOB argument
    BufferTooSmall      = 1001, ///< Output buffer is smaller than required
    UnsupportedAlgorithm= 1002, ///< Requested algorithm not compiled in
    UnsupportedOperation= 1003, ///< Operation not valid in current state/mode

    // ── Cryptographic errors ─────────────────────────────────────────────────
    KeyGenerationFailed = 2000, ///< OQS/OpenSSL key-generation failed
    EncapsulationFailed = 2001, ///< KEM encapsulation failed
    DecapsulationFailed = 2002, ///< KEM decapsulation failed (bad ciphertext)
    SigningFailed        = 2003, ///< DSA signing failed
    VerificationFailed  = 2004, ///< Signature verification failed
    AeadEncryptFailed   = 2005, ///< AEAD encryption failed
    AeadDecryptFailed   = 2006, ///< AEAD decryption / authentication tag mismatch
    HkdfFailed          = 2007, ///< HKDF key-derivation failed
    KeyDerivationFailed = 2008, ///< Generic key derivation failure

    // ── Authentication / policy errors ───────────────────────────────────────
    AuthenticationFailed= 3000, ///< Mutual authentication rejected
    PolicyViolation     = 3001, ///< Operation violates the active cryptographic profile
    DowngradeRejected   = 3002, ///< Mode downgrade attempt blocked by ACPE
    CertificateInvalid  = 3003, ///< Certificate failed validation
    CertificateExpired  = 3004, ///< Certificate is past its validity period
    CertificateRevoked  = 3005, ///< Certificate appears in the revocation list

    // ── Session errors ────────────────────────────────────────────────────────
    SessionNotFound     = 4000, ///< No session matching the provided SessionId
    SessionExpired      = 4001, ///< Session lifetime has elapsed
    ReplayDetected      = 4002, ///< Nonce/counter indicates a replayed message
    NonceExhausted      = 4003, ///< Nonce space is fully consumed; rekey required

    // ── Transport / fragmentation errors ─────────────────────────────────────
    FragmentMissing     = 5000, ///< One or more fragments not received in time
    ReassemblyFailed    = 5001, ///< Fragments cannot be assembled (corrupt/OOO)
    TransportError      = 5002, ///< Underlying channel send/receive failed

    // ── Group / TreeKEM errors ────────────────────────────────────────────────
    GroupMemberNotFound = 6000, ///< NodeId not present in the tree
    TreeUpdateFailed    = 6001, ///< TreeKEM path-secret update failed
    EpochMismatch       = 6002, ///< Received message belongs to a stale epoch

    // ── Internal / system errors ──────────────────────────────────────────────
    InternalError       = 9000, ///< Unexpected internal assertion / OQS failure
    NotImplemented      = 9001, ///< Feature planned but not yet implemented
    AllocationFailed    = 9002, ///< Memory allocation returned null
};

/**
 * @brief Structured error value carrying a code and a human-readable message.
 */
struct Error {
    ErrorCode   code;
    std::string message;

    explicit Error(ErrorCode c) : code(c), message(error_code_to_string(c)) {}
    Error(ErrorCode c, std::string msg) : code(c), message(std::move(msg)) {}

    /// Returns true when the code represents a success sentinel (rare, but valid).
    [[nodiscard]] bool is_ok() const noexcept { return code == ErrorCode::Ok; }

    /// Human-readable name of the error code.
    [[nodiscard]] static std::string_view error_code_to_string(ErrorCode c) noexcept;
};

// ─────────────────────────────────────────────────────────────────────────────
// Result<T> — lightweight sum type for fallible operations
// ─────────────────────────────────────────────────────────────────────────────

namespace detail {

/// Tag type used to disambiguate construction of the error branch.
struct ErrorTag {};

} // namespace detail

/**
 * @brief Discriminated union holding either a value of type T or an Error.
 *
 * Mirrors the std::expected<T, Error> API so migration to C++23 is mechanical:
 *   - has_value() / operator bool() — check success
 *   - value()   — access T (aborts on misuse in debug builds)
 *   - error()   — access Error (aborts on misuse in debug builds)
 *   - value_or(default) — safe accessor with fallback
 *
 * @tparam T  Value type.  Must be move-constructible.  Use void specialisation
 *            for operations that succeed or fail without a return value.
 */
template <typename T>
class Result {
    static_assert(!std::is_reference_v<T>, "Result<T>: T must not be a reference type");

public:
    using value_type = T;
    using error_type = Error;

    // ── Success constructors ─────────────────────────────────────────────────
    // NOLINTNEXTLINE(google-explicit-constructor)
    Result(T value) : storage_(std::move(value)) {}

    // ── Error constructors ────────────────────────────────────────────────────
    // NOLINTNEXTLINE(google-explicit-constructor)
    Result(Error err) : storage_(std::move(err)) {}
    Result(ErrorCode code) : storage_(Error{code}) {}
    Result(ErrorCode code, std::string msg) : storage_(Error{code, std::move(msg)}) {}

    // ── Observers ─────────────────────────────────────────────────────────────
    [[nodiscard]] bool has_value() const noexcept {
        return std::holds_alternative<T>(storage_);
    }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] T& value() & {
        if (!has_value()) [[unlikely]] { abort_on_bad_access(); }
        return std::get<T>(storage_);
    }
    [[nodiscard]] const T& value() const& {
        if (!has_value()) [[unlikely]] { abort_on_bad_access(); }
        return std::get<T>(storage_);
    }
    [[nodiscard]] T&& value() && {
        if (!has_value()) [[unlikely]] { abort_on_bad_access(); }
        return std::get<T>(std::move(storage_));
    }

    [[nodiscard]] const Error& error() const& {
        if (has_value()) [[unlikely]] { abort_on_bad_error_access(); }
        return std::get<Error>(storage_);
    }
    [[nodiscard]] Error& error() & {
        if (has_value()) [[unlikely]] { abort_on_bad_error_access(); }
        return std::get<Error>(storage_);
    }

    template <typename U>
    [[nodiscard]] T value_or(U&& default_value) const& {
        if (has_value()) return std::get<T>(storage_);
        return static_cast<T>(std::forward<U>(default_value));
    }

    /// Apply a function to the value if present; propagate the error otherwise.
    template <typename F>
    auto and_then(F&& f) & -> decltype(f(std::declval<T&>())) {
        if (has_value()) return f(value());
        return error();
    }
    template <typename F>
    auto and_then(F&& f) const& -> decltype(f(std::declval<const T&>())) {
        if (has_value()) return f(value());
        return error();
    }

    /// Apply a function to the error if present; propagate the value otherwise.
    template <typename F>
    Result<T> or_else(F&& f) const& {
        if (!has_value()) return f(error());
        return *this;
    }

private:
    [[noreturn]] static void abort_on_bad_access() noexcept {
        std::fputs("[uav_pqc] FATAL: Result<T>::value() called on an error Result.\n"
                   "          Check has_value() before accessing value().\n",
                   stderr);
        std::abort();
    }
    [[noreturn]] static void abort_on_bad_error_access() noexcept {
        std::fputs("[uav_pqc] FATAL: Result<T>::error() called on a success Result.\n"
                   "          Check !has_value() before accessing error().\n",
                   stderr);
        std::abort();
    }

    std::variant<T, Error> storage_;
};

// ── void specialisation ───────────────────────────────────────────────────────

template <>
class Result<void> {
public:
    using value_type = void;
    using error_type = Error;

    /// Construct a successful void result.
    Result() : error_(std::nullopt) {}

    // NOLINTNEXTLINE(google-explicit-constructor)
    Result(Error err) : error_(std::move(err)) {}
    Result(ErrorCode code) : error_(Error{code}) {}
    Result(ErrorCode code, std::string msg) : error_(Error{code, std::move(msg)}) {}

    [[nodiscard]] bool has_value() const noexcept { return !error_.has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] const Error& error() const {
        if (!error_.has_value()) [[unlikely]] { abort_on_bad_error_access(); }
        return *error_;
    }

    template <typename F>
    Result<void> and_then(F&& f) {
        if (has_value()) return f();
        return *this;
    }

private:
    [[noreturn]] static void abort_on_bad_error_access() noexcept {
        std::fputs("[uav_pqc] FATAL: Result<void>::error() called on a success Result.\n",
                   stderr);
        std::abort();
    }
    std::optional<Error> error_;
};

/// Convenience alias for operations that produce no value on success.
using VoidResult = Result<void>;

/// Construct a successful Result<void> (zero-overhead factory).
[[nodiscard]] inline VoidResult ok() { return {}; }

/// Construct a Result<T> carrying a value.
template <typename T>
[[nodiscard]] inline Result<T> ok(T value) { return Result<T>{std::move(value)}; }

/// Construct an error result from an ErrorCode.
template <typename T = void>
[[nodiscard]] inline Result<T> err(ErrorCode code) { return Result<T>{Error{code}}; }

/// Construct an error result from an ErrorCode and message.
template <typename T = void>
[[nodiscard]] inline Result<T> err(ErrorCode code, std::string msg) {
    return Result<T>{Error{code, std::move(msg)}};
}

/// Construct an error result from a pre-built Error.
template <typename T = void>
[[nodiscard]] inline Result<T> err(Error error) { return Result<T>{std::move(error)}; }

} // namespace uav_pqc
