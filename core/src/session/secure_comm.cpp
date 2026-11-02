// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file secure_comm.cpp
 * @brief Secure communication layer encrypt/decrypt and fragment orchestration.
 */

#include "uav_pqc/session/secure_comm.hpp"
#include "uav_pqc/common/logging.hpp"
#include <algorithm>

namespace uav_pqc::session {

SecureCommLayer::SecureCommLayer(std::shared_ptr<session::Session> session, std::size_t mtu)
    : session_(std::move(session)), mtu_(mtu) {
    UAV_PQC_LOG_DEBUG("session", "SecureCommLayer initialized with session {} mtu={}",
                      to_hex(ByteSpan{session_->id().data(), session_->id().size()}), mtu_);
}

Result<std::vector<transport::Fragment>> SecureCommLayer::protect_and_fragment(
    const AppMessage& msg,
    transport::StreamId stream_id,
    ByteSpan aad) {
    
    if (!session_) {
        return err<std::vector<transport::Fragment>>(ErrorCode::InternalError, "Null session pointer");
    }

    // Pack cleartext: category (1 byte) || payload (n bytes)
    Bytes plaintext;
    plaintext.reserve(1 + msg.payload.size());
    plaintext.push_back(static_cast<std::byte>(msg.category));
    plaintext.insert(plaintext.end(), msg.payload.begin(), msg.payload.end());

    // Encrypt the composite packet
    auto enc_r = session_->encrypt(plaintext, aad);
    if (!enc_r) {
        UAV_PQC_LOG_ERROR("session", "Failed to encrypt application message category={}", 
                          static_cast<std::uint8_t>(msg.category));
        return err<std::vector<transport::Fragment>>(enc_r.error());
    }

    UAV_PQC_LOG_DEBUG("session", "Protected application message category={} plaintext_size={} ciphertext_size={}",
                      static_cast<std::uint8_t>(msg.category), plaintext.size(), enc_r.value().size());

    // Fragment the ciphertext
    return transport::fragment_message(enc_r.value(), mtu_, stream_id);
}

Result<std::optional<AppMessage>> SecureCommLayer::process_incoming_fragment(
    const transport::Fragment& frag,
    Timestamp now_ms,
    ByteSpan aad) {
    
    if (!session_) {
        return err<std::optional<AppMessage>>(ErrorCode::InternalError, "Null session pointer");
    }

    // Feed to reassembly engine
    auto reassemble_r = reassembler_.feed(frag, now_ms);
    if (!reassemble_r) {
        UAV_PQC_LOG_ERROR("session", "Failed to feed fragment to reassembler stream_id={} index={}", 
                          frag.stream_id, frag.fragment_index);
        return err<std::optional<AppMessage>>(reassemble_r.error());
    }

    // If reassembly is not complete, return nullopt
    if (!reassemble_r.value().has_value()) {
        return ok<std::optional<AppMessage>>(std::nullopt);
    }

    const auto& composite_ct = reassemble_r.value().value();

    // Decrypt the reassembled ciphertext
    auto dec_r = session_->decrypt(composite_ct, aad);
    if (!dec_r) {
        UAV_PQC_LOG_WARN("session", "Failed to decrypt reassembled message size={}", composite_ct.size());
        return err<std::optional<AppMessage>>(dec_r.error());
    }

    const auto& plaintext = dec_r.value();
    if (plaintext.empty()) {
        return err<std::optional<AppMessage>>(ErrorCode::AeadDecryptFailed, "Decrypted plaintext is empty");
    }

    // Unpack: category (1 byte) || payload (n bytes)
    std::uint8_t cat_val = static_cast<std::uint8_t>(plaintext[0]);
    if (cat_val < static_cast<std::uint8_t>(AppCategory::Telemetry) || 
        cat_val > static_cast<std::uint8_t>(AppCategory::MissionUpdates)) {
        return err<std::optional<AppMessage>>(ErrorCode::InvalidArgument, "Invalid application category byte");
    }

    AppMessage msg;
    msg.category = static_cast<AppCategory>(cat_val);
    msg.payload.assign(plaintext.begin() + 1, plaintext.end());

    UAV_PQC_LOG_INFO("session", "Successfully reassembled and verified app message category={} payload_size={}",
                     cat_val, msg.payload.size());

    return ok<std::optional<AppMessage>>(std::move(msg));
}

} // namespace uav_pqc::session
