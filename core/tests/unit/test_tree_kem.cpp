// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_tree_kem.cpp — Unit tests for TreeKEM group key management

#include "uav_pqc/group/tree_kem.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::group;

TEST(TreeKemTest, SingleMemberGroupKeyGen) {
    auto suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    auto tk = make_tree_kem(suite);

    // Initial group epoch is 0
    EXPECT_EQ(tk->current_epoch(), 0u);

    // We register a callback when group key is ready
    bool key_ready = false;
    tk->set_group_key_ready_fn([&](const GroupKey& gk) {
        key_ready = true;
        EXPECT_EQ(gk.epoch(), 1u);
    });

    crypto::MlKem mlkem(crypto::MlKem::Level::Kem768);
    auto leaf_kp = mlkem.generate_keypair().value();

    SwarmMember member1{
        .node_id = {std::byte{0x01}},
        .leaf_key = leaf_kp.public_key,
        .leaf_index = 0,
        .joined_at_ms = 1000
    };

    auto update_res = tk->add_member(member1, suite);
    ASSERT_TRUE(update_res.has_value()) << update_res.error().message;
    EXPECT_EQ(tk->current_epoch(), 1u);

    // Process update on member1 side
    auto process_res = tk->process_update(update_res.value(), member1.node_id, leaf_kp.private_key);
    ASSERT_TRUE(process_res.has_value()) << process_res.error().message;

    EXPECT_TRUE(key_ready);
    EXPECT_EQ(process_res.value().epoch(), 1u);
    EXPECT_EQ(process_res.value().make_aead_key().data.size(), 32u);
}

TEST(TreeKemTest, MultiMemberJoinAndLeave) {
    auto suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    auto tk = make_tree_kem(suite);

    crypto::MlKem mlkem(crypto::MlKem::Level::Kem768);
    auto kp1 = mlkem.generate_keypair().value();
    auto kp2 = mlkem.generate_keypair().value();

    SwarmMember m1{
        .node_id = {std::byte{0x01}},
        .leaf_key = kp1.public_key,
        .leaf_index = 0,
        .joined_at_ms = 1000
    };
    SwarmMember m2{
        .node_id = {std::byte{0x02}},
        .leaf_key = kp2.public_key,
        .leaf_index = 1,
        .joined_at_ms = 2000
    };

    // Add m1
    auto up1 = tk->add_member(m1, suite).value();
    EXPECT_TRUE(tk->process_update(up1, m1.node_id, kp1.private_key).has_value());

    // Add m2
    auto up2 = tk->add_member(m2, suite).value();
    EXPECT_EQ(tk->current_epoch(), 2u);

    // Both process update
    auto gk1 = tk->process_update(up2, m1.node_id, kp1.private_key).value();
    auto gk2 = tk->process_update(up2, m2.node_id, kp2.private_key).value();

    // Verify both derived the exact same group key
    EXPECT_EQ(gk1.epoch(), 2u);
    EXPECT_EQ(gk1.make_aead_key().data.bytes(), gk2.make_aead_key().data.bytes());

    // Remove m2
    auto up3 = tk->remove_member(m2.node_id, RekeyReason::MemberLeft, suite).value();
    EXPECT_EQ(tk->current_epoch(), 3u);

    // Remaining member m1 processes the leave rekey
    auto gk3 = tk->process_update(up3, m1.node_id, kp1.private_key).value();
    EXPECT_EQ(gk3.epoch(), 3u);
    EXPECT_NE(gk3.make_aead_key().data.bytes(), gk1.make_aead_key().data.bytes()); // should be a fresh rotated key
}

TEST(TreeKemTest, SerializationAndVisualization) {
    auto suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    auto tk = make_tree_kem(suite);

    crypto::MlKem mlkem(crypto::MlKem::Level::Kem768);
    auto kp1 = mlkem.generate_keypair().value();
    auto kp2 = mlkem.generate_keypair().value();

    SwarmMember m1{
        .node_id = {std::byte{0x01}},
        .leaf_key = kp1.public_key,
        .leaf_index = 0,
        .joined_at_ms = 1000
    };
    SwarmMember m2{
        .node_id = {std::byte{0x02}},
        .leaf_key = kp2.public_key,
        .leaf_index = 1,
        .joined_at_ms = 2000
    };

    // Add m1
    auto up1 = tk->add_member(m1, suite).value();
    EXPECT_TRUE(tk->process_update(up1, m1.node_id, kp1.private_key).has_value());

    // Add m2
    auto up2 = tk->add_member(m2, suite).value();

    // ── Test Visualization ───────────────────────────────────────────────────
    std::string tree_vis = tk->visualize();
    EXPECT_FALSE(tree_vis.empty());
    EXPECT_NE(tree_vis.find("ACTIVE"), std::string::npos);

    // ── Test TreeKem State Serialization ──────────────────────────────────────
    auto ser_tree_r = tk->serialize();
    ASSERT_TRUE(ser_tree_r.has_value()) << ser_tree_r.error().message;

    auto tk2 = make_tree_kem(suite);
    auto deser_tree_r = tk2->deserialize(ser_tree_r.value());
    ASSERT_TRUE(deser_tree_r.has_value()) << deser_tree_r.error().message;
    EXPECT_EQ(tk2->current_epoch(), tk->current_epoch());
    EXPECT_EQ(tk2->membership().size(), tk->membership().size());

    // ── Test GroupKeyUpdate Serialization ─────────────────────────────────────
    auto ser_update_r = serialize_group_key_update(up2);
    ASSERT_TRUE(ser_update_r.has_value()) << ser_update_r.error().message;

    auto deser_update_r = deserialize_group_key_update(ser_update_r.value());
    ASSERT_TRUE(deser_update_r.has_value()) << deser_update_r.error().message;

    EXPECT_EQ(deser_update_r.value().new_epoch, up2.new_epoch);
    EXPECT_EQ(deser_update_r.value().reason, up2.reason);
    EXPECT_EQ(deser_update_r.value().commit_digest, up2.commit_digest);
    EXPECT_EQ(deser_update_r.value().path_secrets.size(), up2.path_secrets.size());
}

