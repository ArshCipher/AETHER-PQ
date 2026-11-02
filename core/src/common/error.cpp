// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file error.cpp
 * @brief Error code to string mapping and Result<T> abort helpers.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"

#include <cassert>
#include <cstdlib>
#include <cstdio>

namespace uav_pqc {

// ── Error::error_code_to_string ───────────────────────────────────────────────

std::string_view Error::error_code_to_string(ErrorCode c) noexcept {
    switch (c) {
        case ErrorCode::Ok:                   return "Ok";
        case ErrorCode::InvalidArgument:      return "InvalidArgument";
        case ErrorCode::BufferTooSmall:       return "BufferTooSmall";
        case ErrorCode::UnsupportedAlgorithm: return "UnsupportedAlgorithm";
        case ErrorCode::UnsupportedOperation: return "UnsupportedOperation";
        case ErrorCode::KeyGenerationFailed:  return "KeyGenerationFailed";
        case ErrorCode::EncapsulationFailed:  return "EncapsulationFailed";
        case ErrorCode::DecapsulationFailed:  return "DecapsulationFailed";
        case ErrorCode::SigningFailed:         return "SigningFailed";
        case ErrorCode::VerificationFailed:   return "VerificationFailed";
        case ErrorCode::AeadEncryptFailed:    return "AeadEncryptFailed";
        case ErrorCode::AeadDecryptFailed:    return "AeadDecryptFailed";
        case ErrorCode::HkdfFailed:           return "HkdfFailed";
        case ErrorCode::KeyDerivationFailed:  return "KeyDerivationFailed";
        case ErrorCode::AuthenticationFailed: return "AuthenticationFailed";
        case ErrorCode::PolicyViolation:      return "PolicyViolation";
        case ErrorCode::DowngradeRejected:    return "DowngradeRejected";
        case ErrorCode::CertificateInvalid:   return "CertificateInvalid";
        case ErrorCode::CertificateExpired:   return "CertificateExpired";
        case ErrorCode::CertificateRevoked:   return "CertificateRevoked";
        case ErrorCode::SessionNotFound:      return "SessionNotFound";
        case ErrorCode::SessionExpired:       return "SessionExpired";
        case ErrorCode::ReplayDetected:       return "ReplayDetected";
        case ErrorCode::NonceExhausted:       return "NonceExhausted";
        case ErrorCode::FragmentMissing:      return "FragmentMissing";
        case ErrorCode::ReassemblyFailed:     return "ReassemblyFailed";
        case ErrorCode::TransportError:       return "TransportError";
        case ErrorCode::GroupMemberNotFound:  return "GroupMemberNotFound";
        case ErrorCode::TreeUpdateFailed:     return "TreeUpdateFailed";
        case ErrorCode::EpochMismatch:        return "EpochMismatch";
        case ErrorCode::InternalError:        return "InternalError";
        case ErrorCode::NotImplemented:       return "NotImplemented";
        case ErrorCode::AllocationFailed:     return "AllocationFailed";
    }
    return "UnknownError";
}

} // namespace uav_pqc
