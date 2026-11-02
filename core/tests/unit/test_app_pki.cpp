// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/identity/trust_chain.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"

using namespace uav_pqc;
using namespace uav_pqc::app;
using namespace uav_pqc::identity;

TEST(AppPkiTest, CompletePkiFlow) {
    CertificateAuthority ca;
    
    // 1. Root Certificate Generation
    auto root_r = ca.generate_root_certificate("Root_CA", 3600000, 1000);
    ASSERT_TRUE(root_r.has_value());
    
    auto root_cert = root_r.value();
    EXPECT_EQ(root_cert.subject_name(), "Root_CA");
    EXPECT_EQ(root_cert.subject_node_id(), root_cert.issuer_node_id());
    EXPECT_EQ(root_cert.not_before_ms(), 1000u);
    EXPECT_EQ(root_cert.not_after_ms(), 3600000u + 1000u);
    
    // Check that root cert carries actual ML-DSA signature
    EXPECT_FALSE(root_cert.signature().empty());

    // 2. Certificate Issuance
    crypto::MlDsa mldsa(crypto::MlDsa::Level::Dsa65);
    auto uav_kp_r = mldsa.generate_keypair();
    ASSERT_TRUE(uav_kp_r.has_value());

    crypto::EcdsaP256 ecdsa;
    auto uav_ecdsa_kp_r = ecdsa.generate_keypair();
    ASSERT_TRUE(uav_ecdsa_kp_r.has_value());

    NodeId uav_id{};
    uav_id[0] = std::byte{0x0A};
    
    auto uav_cert_r = ca.issue_certificate(
        "UAV_01",
        uav_id,
        uav_ecdsa_kp_r.value().public_key,
        uav_kp_r.value().public_key,
        1800000, // lifetime = 30 min
        1000     // now
    );
    ASSERT_TRUE(uav_cert_r.has_value());
    
    auto uav_cert = uav_cert_r.value();
    EXPECT_EQ(uav_cert.subject_name(), "UAV_01");
    EXPECT_EQ(uav_cert.subject_node_id(), uav_id);
    EXPECT_EQ(uav_cert.issuer_node_id(), ca.get_ca_node_id());
    EXPECT_FALSE(uav_cert.signature().empty());

    // 3. Trust Chain Verification (Actual signature verification!)
    std::vector<Certificate> anchors = { root_cert };
    TrustChain chain(anchors);
    
    std::vector<Certificate> cert_path = { uav_cert, root_cert };
    auto val_r = chain.validate(cert_path, 1500);
    ASSERT_TRUE(val_r.has_value());
    EXPECT_TRUE(val_r.value().is_pqc_signed);
    EXPECT_TRUE(val_r.value().is_ecdsa_signed); // carries both since we issued as hybrid

    // 4. Certificate Renewal
    auto renew_r = ca.renew_certificate(uav_cert, 3600000, 2000);
    ASSERT_TRUE(renew_r.has_value());
    
    auto renewed_cert = renew_r.value();
    EXPECT_EQ(renewed_cert.subject_name(), "UAV_01");
    EXPECT_EQ(renewed_cert.not_before_ms(), 2000u);
    EXPECT_EQ(renewed_cert.not_after_ms(), 3600000u + 2000u);

    // 5. Certificate Revocation & CRL exports
    auto rev_r = ca.revoke_certificate(uav_id, 2500, 1); // reason 1 = keyCompromise
    ASSERT_TRUE(rev_r.has_value());

    auto crl_r = ca.generate_crl(3000);
    ASSERT_TRUE(crl_r.has_value());
    EXPECT_FALSE(crl_r.value().empty());

    // Test importing CRL into validation blocklist
    chain.revoke(uav_id);
    auto val_rev_r = chain.validate(cert_path, 3000);
    EXPECT_FALSE(val_rev_r.has_value()); // validation must fail for revoked certs
    EXPECT_EQ(val_rev_r.error().code, ErrorCode::CertificateRevoked);

    // 6. DB Persistence / Export / Import
    std::string db_path = "./test_pki_db.json";
    auto save_r = ca.save_to_file(db_path);
    ASSERT_TRUE(save_r.has_value());

    CertificateAuthority loaded_ca;
    auto load_r = loaded_ca.load_from_file(db_path);
    ASSERT_TRUE(load_r.has_value());

    EXPECT_EQ(loaded_ca.get_ca_node_id(), ca.get_ca_node_id());
    ASSERT_TRUE(loaded_ca.get_ca_certificate().has_value());
    EXPECT_EQ(loaded_ca.get_ca_certificate()->raw_der(), ca.get_ca_certificate()->raw_der());
    EXPECT_EQ(loaded_ca.get_issued_certificates().size(), ca.get_issued_certificates().size());
    EXPECT_EQ(loaded_ca.get_revoked_node_ids().size(), ca.get_revoked_node_ids().size());

    // Clean up temporary database file
    std::remove(db_path.c_str());
}
