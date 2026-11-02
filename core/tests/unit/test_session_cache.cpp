// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_session_cache.cpp — Unit tests for SessionCache

#include "uav_pqc/session/session_cache.hpp"
#include "uav_pqc/session/session.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::session;

static Session create_dummy_session(const SessionId& id, const NodeId& peer) {
    protocol::CipherSuite suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    crypto::AeadKey send_key, recv_key;
    send_key.data.resize(32);
    std::fill(send_key.data.data(), send_key.data.data() + send_key.data.size(), std::byte{0x01});
    recv_key.data.resize(32);
    std::fill(recv_key.data.data(), recv_key.data.data() + recv_key.data.size(), std::byte{0x02});
    std::array<std::byte, 4> send_prefix{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
    std::array<std::byte, 4> recv_prefix{std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    return Session{id, peer, suite, std::move(send_key), std::move(recv_key), send_prefix, recv_prefix, 100000};
}

TEST(SessionCacheTest, StoreAndRetrieve) {
    SessionCache cache(10, 5000);
    SessionId id{std::byte{0x01}};
    NodeId peer{std::byte{0x02}};

    Session session = create_dummy_session(id, peer);
    auto store_res = cache.store(std::move(session), 1000);
    EXPECT_TRUE(store_res.has_value());

    auto ret_res = cache.retrieve(id, peer, 2000);
    ASSERT_TRUE(ret_res.has_value());
    EXPECT_EQ(ret_res.value().id(), id);
    EXPECT_EQ(ret_res.value().peer_node_id(), peer);
}

TEST(SessionCacheTest, ExpiryTTL) {
    SessionCache cache(10, 1000); // 1s TTL
    SessionId id{std::byte{0x01}};
    NodeId peer{std::byte{0x02}};

    Session session = create_dummy_session(id, peer);
    auto store_res = cache.store(std::move(session), 1000);
    EXPECT_TRUE(store_res.has_value());

    // Try retrieve after TTL (at t=2500ms, which is > 1000ms + 1000ms TTL)
    auto ret_res = cache.retrieve(id, peer, 2500);
    EXPECT_FALSE(ret_res.has_value());
    EXPECT_EQ(ret_res.error().code, ErrorCode::SessionExpired);
}

TEST(SessionCacheTest, PeerMismatchRejection) {
    SessionCache cache(10, 5000);
    SessionId id{std::byte{0x01}};
    NodeId peer{std::byte{0x02}};
    NodeId bad_peer{std::byte{0x99}};

    Session session = create_dummy_session(id, peer);
    auto store_res = cache.store(std::move(session), 1000);
    EXPECT_TRUE(store_res.has_value());

    auto ret_res = cache.retrieve(id, bad_peer, 2000);
    EXPECT_FALSE(ret_res.has_value());
    EXPECT_EQ(ret_res.error().code, ErrorCode::AuthenticationFailed);
}

TEST(SessionCacheTest, LRUEviction) {
    SessionCache cache(2, 5000); // capacity 2
    SessionId id1{std::byte{0x01}};
    SessionId id2{std::byte{0x02}};
    SessionId id3{std::byte{0x03}};
    NodeId peer{std::byte{0x02}};

    Session s1 = create_dummy_session(id1, peer);
    Session s2 = create_dummy_session(id2, peer);
    Session s3 = create_dummy_session(id3, peer);

    EXPECT_TRUE(cache.store(std::move(s1), 1000, 2000).has_value()); // expires at 3000
    EXPECT_TRUE(cache.store(std::move(s2), 1000, 4000).has_value()); // expires at 5000

    // Store third session. Since it's full, it will evict the one expiring first (s1)
    EXPECT_TRUE(cache.store(std::move(s3), 1000, 5000).has_value());

    // s1 should be evicted
    auto ret1 = cache.retrieve(id1, peer, 1100);
    EXPECT_FALSE(ret1.has_value());

    // s2 and s3 should be present
    auto ret2 = cache.retrieve(id2, peer, 1100);
    EXPECT_TRUE(ret2.has_value());
}
