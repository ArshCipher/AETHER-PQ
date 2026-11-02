// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include "uav_pqc/protocol/auth.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"

using namespace uav_pqc;
using namespace uav_pqc::protocol;
using namespace uav_pqc::app;

class AuthTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup CA
        ca_node_id_[0] = std::byte{0xCA};
        crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
        auto kp_r = mldsa.generate_keypair();
        ASSERT_TRUE(kp_r.has_value());
        ca_ = std::make_unique<CertificateAuthority>(ca_node_id_, std::move(kp_r.value()));
        
        auto ca_cert_r = ca_->generate_root_certificate("Root_CA", 31536000000ULL, 1000);
        ASSERT_TRUE(ca_cert_r.has_value());
        ca_cert_ = ca_cert_r.value();

        // Setup GCS keys & cert
        gcs_mldsa_kp_ = mldsa.generate_keypair().value();
        crypto::EcdsaP256 ecdsa;
        gcs_ecdsa_kp_ = ecdsa.generate_keypair().value();
        
        NodeId gcs_node_id{};
        gcs_node_id[0] = std::byte{0x01};
        auto gcs_cert_r = ca_->issue_certificate("GCS", gcs_node_id, gcs_ecdsa_kp_.public_key, gcs_mldsa_kp_.public_key, 360000, 1000);
        ASSERT_TRUE(gcs_cert_r.has_value());
        gcs_cert_ = gcs_cert_r.value();

        // Setup UAV keys & cert
        uav_mldsa_kp_ = mldsa.generate_keypair().value();
        uav_ecdsa_kp_ = ecdsa.generate_keypair().value();
        
        NodeId uav_node_id{};
        uav_node_id[0] = std::byte{0x02};
        auto uav_cert_r = ca_->issue_certificate("UAV_01", uav_node_id, uav_ecdsa_kp_.public_key, uav_mldsa_kp_.public_key, 360000, 1000);
        ASSERT_TRUE(uav_cert_r.has_value());
        uav_cert_ = uav_cert_r.value();
    }

    NodeId ca_node_id_{};
    identity::Certificate ca_cert_;
    std::unique_ptr<CertificateAuthority> ca_;
    
    crypto::DsaKeyPair gcs_mldsa_kp_;
    crypto::DsaKeyPair gcs_ecdsa_kp_;
    identity::Certificate gcs_cert_;

    crypto::DsaKeyPair uav_mldsa_kp_;
    crypto::DsaKeyPair uav_ecdsa_kp_;
    identity::Certificate uav_cert_;
};

TEST_F(AuthTest, MutualAuthenticationSuccess) {
    UavAuthInitiator uav(uav_cert_, uav_mldsa_kp_, ca_cert_);
    GcsAuthResponder gcs(gcs_cert_, gcs_mldsa_kp_, ca_cert_);

    Timestamp now = 10000;

    // 1. UAV initiates AUTH_REQ
    auto req_pkt_r = uav.initiate(now);
    ASSERT_TRUE(req_pkt_r.has_value());
    EXPECT_EQ(uav.state(), HandshakeState::WaitServerHello);

    // 2. GCS processes request and generates AUTH_CHALLENGE
    auto ch_pkt_r = gcs.handle_req(req_pkt_r.value(), now);
    ASSERT_TRUE(ch_pkt_r.has_value());
    EXPECT_EQ(gcs.state(), HandshakeState::WaitClientAuth);

    // 3. UAV handles GCS challenge and generates AUTH_RESPONSE
    auto resp_pkt_r = uav.handle_challenge(ch_pkt_r.value(), now);
    ASSERT_TRUE(resp_pkt_r.has_value());
    EXPECT_EQ(uav.state(), HandshakeState::WaitFinished);

    // 4. GCS processes response, generates GCS session, and returns AUTH_SUCCESS
    auto succ_pkt_r = gcs.handle_response(resp_pkt_r.value(), now);
    ASSERT_TRUE(succ_pkt_r.has_value());
    EXPECT_EQ(gcs.state(), HandshakeState::Complete);

    // 5. UAV processes GCS success and generates UAV session
    auto verify_r = uav.handle_success(succ_pkt_r.value(), now);
    ASSERT_TRUE(verify_r.has_value());
    EXPECT_EQ(uav.state(), HandshakeState::Complete);

    // 6. Verify derived sessions work by doing an encrypted round-trip loopback
    auto uav_res_r = uav.result();
    ASSERT_TRUE(uav_res_r.has_value());
    auto gcs_res_r = gcs.result();
    ASSERT_TRUE(gcs_res_r.has_value());

    auto& uav_session = uav_res_r.value().session;
    auto& gcs_session = gcs_res_r.value().session;

    Bytes pt = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    Bytes aad = {std::byte{0x01}, std::byte{0x02}};

    // UAV encrypts, GCS decrypts
    auto ct_r = uav_session.encrypt(pt, aad);
    ASSERT_TRUE(ct_r.has_value());
    auto dt_r = gcs_session.decrypt(ct_r.value(), aad);
    ASSERT_TRUE(dt_r.has_value());
    EXPECT_EQ(dt_r.value(), pt);

    // GCS encrypts, UAV decrypts
    auto ct2_r = gcs_session.encrypt(pt, aad);
    ASSERT_TRUE(ct2_r.has_value());
    auto dt2_r = uav_session.decrypt(ct2_r.value(), aad);
    ASSERT_TRUE(dt2_r.has_value());
    EXPECT_EQ(dt2_r.value(), pt);
}

TEST_F(AuthTest, ExpiredTimestampRejection) {
    UavAuthInitiator uav(uav_cert_, uav_mldsa_kp_, ca_cert_);
    GcsAuthResponder gcs(gcs_cert_, gcs_mldsa_kp_, ca_cert_);

    auto req_pkt_r = uav.initiate(10000);
    ASSERT_TRUE(req_pkt_r.has_value());

    // GCS handles with an expired timestamp (diff = 400s > 300s tolerance)
    auto ch_pkt_r = gcs.handle_req(req_pkt_r.value(), 410000);
    ASSERT_TRUE(ch_pkt_r.has_value());

    // The output should be a reject AUTH_FAIL message
    auto handle_r = uav.handle_challenge(ch_pkt_r.value(), 410000);
    EXPECT_FALSE(handle_r.has_value());
    EXPECT_EQ(uav.state(), HandshakeState::Failed);
}

TEST_F(AuthTest, NonceReplayRejection) {
    UavAuthInitiator uav1(uav_cert_, uav_mldsa_kp_, ca_cert_);
    UavAuthInitiator uav2(uav_cert_, uav_mldsa_kp_, ca_cert_);
    GcsAuthResponder gcs(gcs_cert_, gcs_mldsa_kp_, ca_cert_);

    Timestamp now = 10000;
    auto req_pkt_r = uav1.initiate(now);
    ASSERT_TRUE(req_pkt_r.has_value());

    // First handle: OK
    auto ch_pkt_r1 = gcs.handle_req(req_pkt_r.value(), now);
    ASSERT_TRUE(ch_pkt_r1.has_value());

    // Replay request: rejected
    auto ch_pkt_r2 = gcs.handle_req(req_pkt_r.value(), now);
    ASSERT_TRUE(ch_pkt_r2.has_value());

    auto handle_r = uav2.handle_challenge(ch_pkt_r2.value(), now);
    EXPECT_FALSE(handle_r.has_value());
}
