#include <gtest/gtest.h>

#include "uav_pqc/session/d2d_manager.hpp"
#include "uav_pqc/protocol/d2d_messages.hpp"
#include "uav_pqc/app/d2d_coordinator.hpp"
#include "uav_pqc/policy/acpe.hpp"

using namespace uav_pqc;

TEST(D2DTest, ProtocolPayloadSerialization) {
    protocol::D2DSessionReqPayload req;
    req.initiator_node_id = {std::byte{0x01}, std::byte{0x02}};
    req.target_node_id = {std::byte{0x03}, std::byte{0x04}};
    req.requested_lifetime_seconds = 600;
    req.traffic_reason = "Telemetry sync";

    Bytes bytes = req.serialize();
    auto deser_r = protocol::D2DSessionReqPayload::deserialize(bytes);
    ASSERT_TRUE(deser_r.has_value());
    EXPECT_EQ(deser_r.value().initiator_node_id, req.initiator_node_id);
    EXPECT_EQ(deser_r.value().target_node_id, req.target_node_id);
    EXPECT_EQ(deser_r.value().requested_lifetime_seconds, 600u);
    EXPECT_EQ(deser_r.value().traffic_reason, "Telemetry sync");
}

TEST(D2DTest, SessionManagerLifecycleAndZeroization) {
    session::D2DSessionManager manager;
    Timestamp now = 100000;

    session::D2DSession sess;
    SessionId sess_id = {std::byte{0x10}, std::byte{0x20}};
    sess.session_id = sess_id;
    sess.local_node_id = {std::byte{0x01}};
    sess.peer_node_id = {std::byte{0x02}};
    sess.peer_ip = "192.168.1.10";
    sess.peer_port = 9001;
    sess.session_key = SecureBytes(32); // 256-bit key
    sess.lifetime_seconds = 10;
    sess.created_at = now;
    sess.expires_at = now + 10000; // 10s expiration
    sess.last_active_at = now;

    auto add_res = manager.add_session(std::move(sess));
    ASSERT_TRUE(add_res.has_value());

    auto fetched = manager.get_session(sess_id);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(fetched->peer_ip, "192.168.1.10");

    // Encrypt and decrypt a payload
    std::string msg = "Secret D2D Telemetry Payload";
    Bytes plaintext(reinterpret_cast<const std::byte*>(msg.data()), reinterpret_cast<const std::byte*>(msg.data()) + msg.size());

    auto enc_res = manager.encrypt_payload(sess_id, plaintext, now + 1000);
    ASSERT_TRUE(enc_res.has_value());

    auto dec_res = manager.decrypt_payload(sess_id, enc_res.value(), now + 1000);
    ASSERT_TRUE(dec_res.has_value());
    std::string decrypted(reinterpret_cast<const char*>(dec_res.value().data()), dec_res.value().size());
    EXPECT_EQ(decrypted, msg);

    // Test Expiration Cleanup
    std::size_t pruned = manager.cleanup_expired_sessions(now + 15000); // Exceeded 10s
    EXPECT_EQ(pruned, 1u);
    EXPECT_FALSE(manager.get_session(sess_id).has_value());
}

TEST(D2DTest, ReplayProtection) {
    session::D2DSessionManager manager;
    Timestamp now = 100000;

    session::D2DSession sess;
    SessionId sess_id = {std::byte{0xAB}, std::byte{0xCD}};
    sess.session_id = sess_id;
    sess.session_key = SecureBytes(32);
    sess.lifetime_seconds = 300;
    sess.created_at = now;
    sess.expires_at = now + 300000;
    sess.last_active_at = now;

    manager.add_session(std::move(sess));

    std::string msg = "Test Payload";
    Bytes plaintext(reinterpret_cast<const std::byte*>(msg.data()), reinterpret_cast<const std::byte*>(msg.data()) + msg.size());

    auto enc1 = manager.encrypt_payload(sess_id, plaintext, now);
    auto enc2 = manager.encrypt_payload(sess_id, plaintext, now);

    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());

    // Decrypt seq 0 then seq 1
    auto dec1 = manager.decrypt_payload(sess_id, enc1.value(), now);
    ASSERT_TRUE(dec1.has_value());

    auto dec2 = manager.decrypt_payload(sess_id, enc2.value(), now);
    ASSERT_TRUE(dec2.has_value());

    // Attempting to replay enc1 (older sequence number) must fail!
    auto replay_res = manager.decrypt_payload(sess_id, enc1.value(), now);
    EXPECT_FALSE(replay_res.has_value());
    EXPECT_EQ(replay_res.error().code, ErrorCode::ReplayDetected);
}

TEST(D2DTest, GCSCoordinatorAuthorization) {
    policy::RuleBasedAcpe acpe;
    app::D2DCoordinator coordinator(&acpe);

    protocol::D2DSessionReqPayload req;
    req.initiator_node_id = {std::byte{0x01}};
    req.target_node_id = {std::byte{0x02}};
    req.requested_lifetime_seconds = 300;

    policy::PolicyContext ctx;
    ctx.battery_percent = 90.0;

    // Target offline -> Reject
    auto res_offline = coordinator.coordinate_session_request(
        req, true, false, "127.0.0.1", 9002, "127.0.0.1", 9001, ctx, 1000);
    EXPECT_FALSE(res_offline.has_value());
    EXPECT_EQ(res_offline.error().code, ErrorCode::AuthenticationFailed);

    // Both active -> Success
    auto res_success = coordinator.coordinate_session_request(
        req, true, true, "127.0.0.1", 9002, "127.0.0.1", 9001, ctx, 1000);
    ASSERT_TRUE(res_success.has_value());
    auto [resp_init, resp_target] = std::move(res_success.value());

    EXPECT_EQ(resp_init.session_key.size(), 32u);
    EXPECT_EQ(resp_init.target_ip, "127.0.0.1");
    EXPECT_EQ(resp_init.target_port, 9002);

    EXPECT_EQ(resp_target.target_ip, "127.0.0.1");
    EXPECT_EQ(resp_target.target_port, 9001);
}
