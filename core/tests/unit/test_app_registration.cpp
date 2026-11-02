// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include <fstream>
#include "uav_pqc/protocol/registration.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"

using namespace uav_pqc;
using namespace uav_pqc::protocol;
using namespace uav_pqc::app;

VoidResult save_db_to_file(const RegistrationDatabase& db, const std::string& filepath) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return err(ErrorCode::InternalError, "Failed to open file");
    }
    file << db.serialize_json();
    return ok();
}

VoidResult load_db_from_file(RegistrationDatabase& db, const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return err(ErrorCode::InternalError, "Failed to open file");
    }
    std::string str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return db.deserialize_json(str);
}

class RegistrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup CA
        ca_node_id_[0] = std::byte{0xCA};
        crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
        auto kp_r = mldsa.generate_keypair();
        ASSERT_TRUE(kp_r.has_value());
        
        ca_ = std::make_unique<CertificateAuthority>(ca_node_id_, std::move(kp_r.value()));
        auto ca_cert_r = ca_->generate_root_certificate("Test_Root_CA", 31536000000ULL, 1000);
        ASSERT_TRUE(ca_cert_r.has_value());
        ca_cert_ = ca_cert_r.value();

        // Setup UAV keys
        auto uav_kp_r = mldsa.generate_keypair();
        ASSERT_TRUE(uav_kp_r.has_value());
        uav_mldsa_kp_ = std::move(uav_kp_r.value());

        crypto::EcdsaP256 ecdsa;
        auto uav_ecdsa_kp_r = ecdsa.generate_keypair();
        ASSERT_TRUE(uav_ecdsa_kp_r.has_value());
        uav_ecdsa_kp_ = std::move(uav_ecdsa_kp_r.value());
    }

    NodeId ca_node_id_{};
    identity::Certificate ca_cert_;
    std::unique_ptr<CertificateAuthority> ca_;
    crypto::DsaKeyPair uav_mldsa_kp_;
    crypto::DsaKeyPair uav_ecdsa_kp_;
};

TEST_F(RegistrationTest, SuccessFlow) {
    RegistrationDatabase db;
    GcsRegistrar gcs(db, *ca_);
    UavRegistrar uav;

    Timestamp now = 10000;

    // 1. UAV initiates request
    auto req_pkt_r = uav.initiate_registration("UAV_01", uav_ecdsa_kp_, uav_mldsa_kp_, now);
    ASSERT_TRUE(req_pkt_r.has_value());
    EXPECT_EQ(uav.state(), UavRegistrar::State::Registering);

    // 2. GCS processes and generates ACK
    auto ack_pkt_r = gcs.process_registration_request(req_pkt_r.value(), now);
    ASSERT_TRUE(ack_pkt_r.has_value());

    // 3. UAV handles ACK
    auto handler_r = uav.handle_registration_response(ack_pkt_r.value(), ca_cert_, now);
    ASSERT_TRUE(handler_r.has_value());
    EXPECT_EQ(uav.state(), UavRegistrar::State::Registered);
    ASSERT_TRUE(uav.uav_certificate().has_value());
    EXPECT_EQ(uav.uav_certificate()->subject_name(), "UAV_01");
}

TEST_F(RegistrationTest, ExpiredTimestampRejection) {
    RegistrationDatabase db;
    GcsRegistrar gcs(db, *ca_);
    UavRegistrar uav;

    // UAV sends request at T=10000
    auto req_pkt_r = uav.initiate_registration("UAV_01", uav_ecdsa_kp_, uav_mldsa_kp_, 10000);
    ASSERT_TRUE(req_pkt_r.has_value());

    // GCS processes at T=400000 (diff = 390s > 300s window)
    auto ack_pkt_r = gcs.process_registration_request(req_pkt_r.value(), 400000);
    ASSERT_TRUE(ack_pkt_r.has_value());

    // Should receive a Reject payload
    auto handler_r = uav.handle_registration_response(ack_pkt_r.value(), ca_cert_, 400000);
    EXPECT_FALSE(handler_r.has_value());
    EXPECT_EQ(uav.state(), UavRegistrar::State::Failed);
}

TEST_F(RegistrationTest, NonceReplayRejection) {
    RegistrationDatabase db;
    GcsRegistrar gcs(db, *ca_);
    UavRegistrar uav1;
    UavRegistrar uav2;

    Timestamp now = 10000;
    auto req_pkt_r = uav1.initiate_registration("UAV_01", uav_ecdsa_kp_, uav_mldsa_kp_, now);
    ASSERT_TRUE(req_pkt_r.has_value());

    // First process: OK
    auto ack_pkt_r1 = gcs.process_registration_request(req_pkt_r.value(), now);
    ASSERT_TRUE(ack_pkt_r1.has_value());

    // Second process (replay same packet/nonce): Rejected
    auto ack_pkt_r2 = gcs.process_registration_request(req_pkt_r.value(), now);
    ASSERT_TRUE(ack_pkt_r2.has_value());

    // Verify second is a reject message
    auto handler_r = uav2.handle_registration_response(ack_pkt_r2.value(), ca_cert_, now);
    EXPECT_FALSE(handler_r.has_value());
}

TEST_F(RegistrationTest, DuplicateRejection) {
    RegistrationDatabase db;
    GcsRegistrar gcs(db, *ca_);
    UavRegistrar uav1;
    UavRegistrar uav2;

    Timestamp now = 10000;
    auto req_pkt1_r = uav1.initiate_registration("UAV_01", uav_ecdsa_kp_, uav_mldsa_kp_, now);
    ASSERT_TRUE(req_pkt1_r.has_value());
    auto ack_pkt1_r = gcs.process_registration_request(req_pkt1_r.value(), now);
    ASSERT_TRUE(ack_pkt1_r.has_value());

    // Request with duplicate subject name "UAV_01"
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto kp_other = mldsa.generate_keypair();
    auto req_pkt2_r = uav2.initiate_registration("UAV_01", uav_ecdsa_kp_, kp_other.value(), now);
    ASSERT_TRUE(req_pkt2_r.has_value());

    auto ack_pkt2_r = gcs.process_registration_request(req_pkt2_r.value(), now);
    ASSERT_TRUE(ack_pkt2_r.has_value());

    auto handler_r = uav2.handle_registration_response(ack_pkt2_r.value(), ca_cert_, now);
    EXPECT_FALSE(handler_r.has_value());
}

TEST_F(RegistrationTest, DbPersistence) {
    std::string db_path = "./test_reg_db.json";
    std::remove(db_path.c_str());

    RegistrationDatabase db;
    RegistrationDatabase::Record rec;
    rec.node_id[0] = std::byte{0x01};
    rec.subject_name = "UAV_01";
    rec.mldsa_pub = uav_mldsa_kp_.public_key;
    rec.ecdsa_pub = uav_ecdsa_kp_.public_key;
    
    auto cert_r = ca_->issue_certificate("UAV_01", rec.node_id, rec.ecdsa_pub, rec.mldsa_pub, 360000, 1000);
    ASSERT_TRUE(cert_r.has_value());
    rec.uav_cert = cert_r.value();
    rec.registered_at = 1000;

    ASSERT_TRUE(db.add_record(rec).has_value());
    ASSERT_TRUE(save_db_to_file(db, db_path).has_value());

    RegistrationDatabase db_loaded;
    ASSERT_TRUE(load_db_from_file(db_loaded, db_path).has_value());
    EXPECT_TRUE(db_loaded.is_registered(rec.node_id));
    EXPECT_TRUE(db_loaded.is_subject_name_registered("UAV_01"));

    auto rec_loaded = db_loaded.get_record(rec.node_id);
    ASSERT_TRUE(rec_loaded.has_value());
    EXPECT_EQ(rec_loaded->subject_name, "UAV_01");
    EXPECT_EQ(rec_loaded->mldsa_pub.data, rec.mldsa_pub.data);
    EXPECT_EQ(rec_loaded->uav_cert.raw_der(), rec.uav_cert.raw_der());

    std::remove(db_path.c_str());
}
