// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/identity/certificate.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <string>
#include <vector>
#include <set>
#include <optional>
#include <memory>

namespace uav_pqc::crypto { class ICryptoProvider; }

namespace uav_pqc::protocol {

enum class RegisterRejectReason : std::uint32_t {
    Unknown             = 0,
    DuplicateNodeId     = 1,
    DuplicateSubjectName= 2,
    InvalidSignature    = 3,
    ExpiredTimestamp    = 4,
    ReplayDetected      = 5,
    CaFailure           = 6,
};

/**
 * @brief REGISTER_REQ structure
 */
struct RegisterReq {
    NodeId                  node_id{};
    std::string             subject_name;
    crypto::DsaPublicKey    ecdsa_pub;
    crypto::DsaPublicKey    mldsa_pub;
    Timestamp               timestamp = 0;
    Bytes                   nonce;
    Bytes                   signature;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<RegisterReq> deserialise(ByteSpan data);
    [[nodiscard]] Bytes get_to_be_signed_bytes() const;
};

/**
 * @brief REGISTER_ACK structure
 */
struct RegisterAck {
    identity::Certificate   ca_cert;
    identity::Certificate   uav_cert;
    Bytes                   nonce;
    Bytes                   signature;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<RegisterAck> deserialise(ByteSpan data);
    [[nodiscard]] Bytes get_to_be_signed_bytes() const;
};

/**
 * @brief REGISTER_REJECT structure
 */
struct RegisterReject {
    Bytes                   nonce;
    RegisterRejectReason    reason = RegisterRejectReason::Unknown;
    std::string             description;

    [[nodiscard]] Bytes serialise() const;
    [[nodiscard]] static Result<RegisterReject> deserialise(ByteSpan data);
};

/**
 * @brief Persistent GCS Registration Database
 */
class RegistrationDatabase {
public:
    struct Record {
        NodeId                  node_id;
        std::string             subject_name;
        crypto::DsaPublicKey    ecdsa_pub;
        crypto::DsaPublicKey    mldsa_pub;
        identity::Certificate   uav_cert;
        Timestamp               registered_at = 0;
    };

    RegistrationDatabase() = default;
    ~RegistrationDatabase() = default;

    VoidResult deserialize_json(const std::string& json_str);
    std::string serialize_json() const;

    bool is_registered(const NodeId& node_id) const;
    bool is_subject_name_registered(const std::string& subject_name) const;
    std::optional<Record> get_record(const NodeId& node_id) const;
    
    VoidResult add_record(Record record);
    std::vector<Record> get_all_records() const;

    // Replay protection helpers
    bool check_and_track_nonce(const Bytes& nonce);
    void prune_seen_nonces(Timestamp max_age_ms);
    void clear();

private:
    std::vector<Record> records_;
    std::set<Bytes> seen_nonces_;
};

/**
 * @brief UAV side Registrar state machine
 */
class UavRegistrar {
public:
    enum class State {
        Unregistered,
        Registering,
        Registered,
        Failed,
    };

    UavRegistrar(std::shared_ptr<platform::IClock> clock = nullptr,
                 std::shared_ptr<crypto::ICryptoProvider> provider = nullptr);
    ~UavRegistrar() = default;

    Result<Bytes> initiate_registration(
        const std::string& subject_name,
        const crypto::DsaKeyPair& ecdsa_kp,
        const crypto::DsaKeyPair& mldsa_kp,
        Timestamp now_ms = 0);

    VoidResult handle_registration_response(
        ByteSpan response_msg,
        const identity::Certificate& ca_anchor,
        Timestamp now_ms = 0);

    [[nodiscard]] State state() const noexcept { return state_; }
    [[nodiscard]] const std::optional<identity::Certificate>& uav_certificate() const noexcept { return uav_cert_; }
    [[nodiscard]] const std::optional<identity::Certificate>& ca_certificate() const noexcept { return ca_cert_; }

private:
    State state_ = State::Unregistered;
    std::string subject_name_;
    crypto::DsaKeyPair ecdsa_kp_;
    crypto::DsaKeyPair mldsa_kp_;
    Bytes sent_nonce_;
    std::optional<identity::Certificate> uav_cert_;
    std::optional<identity::Certificate> ca_cert_;
    std::shared_ptr<platform::IClock> clock_;
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider_;
};

/**
 * @brief GCS side Registrar validator
 */
class GcsRegistrar {
public:
    GcsRegistrar(RegistrationDatabase& db, app::ICertificateAuthority& ca, 
                 std::shared_ptr<platform::IClock> clock = nullptr,
                 std::shared_ptr<crypto::ICryptoProvider> provider = nullptr);
    ~GcsRegistrar() = default;

    Result<Bytes> process_registration_request(ByteSpan request_msg, Timestamp now_ms = 0);

private:
    RegistrationDatabase& db_;
    app::ICertificateAuthority& ca_;
    std::shared_ptr<platform::IClock> clock_;
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider_;
};

} // namespace uav_pqc::protocol
