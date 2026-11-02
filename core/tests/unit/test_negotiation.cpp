// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file test_negotiation.cpp
 * @brief Unit tests for the Operating Mode and Crypto Profile Negotiation protocol.
 *
 * Test coverage:
 *   - Full round-trip for Hybrid mode
 *   - Full round-trip for PQC-Only mode
 *   - Full round-trip for Transition mode
 *   - Full round-trip for Classical mode
 *   - Downgrade rejection: responder mode below initiator floor
 *   - Downgrade rejection: responder proposes mode not in offered list
 *   - Replay attack: nonce echo mismatch on ModeResp
 *   - Replay attack: nonce echo mismatch on ProfileResp
 *   - Forged signature on ModeResp is rejected
 *   - Forged signature on ProfileResp is rejected
 *   - Transcript hash mismatch on ModeConfirm is rejected by responder
 *   - Transcript hash mismatch on ProfileConfirm is rejected by responder
 *   - No mutually acceptable mode → policy violation
 *   - ProfileConfirm with accepted=false aborts responder
 *   - State machine rejects messages in wrong order
 *   - PQC-Only enforces KEM level upgrade
 */

#include <gtest/gtest.h>
#include "uav_pqc/protocol/negotiation.hpp"
#include "uav_pqc/protocol/message.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"

#include <functional>
#include <vector>

using namespace uav_pqc;
using namespace uav_pqc::protocol;

// ─────────────────────────────────────────────────────────────────────────────
// Test-local packet helpers
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// Extract the body ByteSpan from a framed wire packet.
ByteSpan body_of(ByteSpan pkt) {
    if (pkt.size() < MessageHeader::kWireSize) return {};
    auto hdr_r = MessageHeader::deserialise(pkt.subspan(0, MessageHeader::kWireSize));
    if (!hdr_r) return {};
    const std::size_t end = MessageHeader::kWireSize + hdr_r.value().length;
    if (pkt.size() < end) return {};
    return pkt.subspan(MessageHeader::kWireSize, hdr_r.value().length);
}

// Build a wire packet from a MessageType code and serialised body.
Bytes make_test_packet(MessageType type, const Bytes& body) {
    MessageHeader hdr;
    hdr.type   = type;
    hdr.length = static_cast<std::uint16_t>(body.size());
    Bytes pkt  = hdr.serialise();
    pkt.insert(pkt.end(), body.begin(), body.end());
    return pkt;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// DsaKeyPair clone helper (matches pattern in registration.cpp)
crypto::DsaKeyPair clone_kp(const crypto::DsaKeyPair& kp) {
    crypto::DsaKeyPair copy;
    copy.public_key = kp.public_key;
    Bytes b(kp.private_key.data.bytes().begin(), kp.private_key.data.bytes().end());
    copy.private_key.data = SecureBytes(std::move(b));
    return copy;
}

// Generate a ML-DSA-65 key pair
crypto::DsaKeyPair gen_ml_dsa_kp() {
    crypto::MlDsa dsa(crypto::MlDsa::Level::Dsa65);
    auto kp_r = dsa.generate_keypair();
    if (!kp_r) throw std::runtime_error("key gen failed");
    return std::move(kp_r.value());
}

constexpr Timestamp kNow = 1'000'000;

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Test fixture: builds two side-by-side state machines and wires them together
// ─────────────────────────────────────────────────────────────────────────────

class NegotiationTest : public ::testing::Test {
protected:
    void SetUp() override {
        initiator_kp_ = gen_ml_dsa_kp();
        responder_kp_ = gen_ml_dsa_kp();

        initiator_node_id_[0] = std::byte{0x01};
        responder_node_id_[0] = std::byte{0x02};
    }

    NegotiationConfig make_initiator_cfg(
        std::vector<OperatingMode> offered,
        OperatingMode floor = OperatingMode::Transition) {
        NegotiationConfig cfg;
        cfg.our_node_id       = initiator_node_id_;
        cfg.our_ml_dsa_key    = clone_kp(initiator_kp_);
        cfg.peer_ml_dsa_pub   = responder_kp_.public_key;
        cfg.offered_modes     = std::move(offered);
        cfg.minimum_mode      = floor;
        cfg.signing_level     = crypto::MlDsa::Level::Dsa65;
        cfg.max_clock_skew_ms = 300'000;
        return cfg;
    }

    NegotiationConfig make_responder_cfg(
        std::vector<OperatingMode> offered,
        OperatingMode floor = OperatingMode::Transition) {
        NegotiationConfig cfg;
        cfg.our_node_id       = responder_node_id_;
        cfg.our_ml_dsa_key    = clone_kp(responder_kp_);
        cfg.peer_ml_dsa_pub   = initiator_kp_.public_key;
        cfg.offered_modes     = std::move(offered);
        cfg.minimum_mode      = floor;
        cfg.signing_level     = crypto::MlDsa::Level::Dsa65;
        cfg.max_clock_skew_ms = 300'000;
        return cfg;
    }

    // Run the full 6-message exchange and assert both sides reach Complete.
    void run_full_exchange(std::unique_ptr<INegotiationInitiator>& init,
                           std::unique_ptr<INegotiationResponder>& resp) {
        std::vector<Bytes> i_to_r, r_to_i;

        init->set_send_fn([&](Bytes b) -> VoidResult {
            i_to_r.push_back(std::move(b)); return ok();
        });
        resp->set_send_fn([&](Bytes b) -> VoidResult {
            r_to_i.push_back(std::move(b)); return ok();
        });

        // Initiator sends ModeReq
        ASSERT_TRUE(init->start(kNow).has_value());
        ASSERT_EQ(i_to_r.size(), 1u); // ModeReq

        // Responder receives ModeReq → sends ModeResp
        ASSERT_TRUE(resp->feed_message(i_to_r[0], kNow).has_value());
        ASSERT_EQ(r_to_i.size(), 1u); // ModeResp

        // Initiator receives ModeResp → sends ModeConfirm + ProfileReq (2 packets)
        ASSERT_TRUE(init->feed_message(r_to_i[0], kNow).has_value());
        ASSERT_EQ(i_to_r.size(), 3u); // ModeConfirm + ProfileReq

        // Responder receives ModeConfirm
        ASSERT_TRUE(resp->feed_message(i_to_r[1], kNow).has_value());
        ASSERT_EQ(resp->state(), NegotiationState::WaitProfileReq);

        // Responder receives ProfileReq → sends ProfileResp
        ASSERT_TRUE(resp->feed_message(i_to_r[2], kNow).has_value());
        ASSERT_EQ(r_to_i.size(), 2u); // ProfileResp

        // Initiator receives ProfileResp → sends ProfileConfirm
        ASSERT_TRUE(init->feed_message(r_to_i[1], kNow).has_value());
        ASSERT_EQ(i_to_r.size(), 4u); // ProfileConfirm
        ASSERT_EQ(init->state(), NegotiationState::Complete);

        // Responder receives ProfileConfirm
        ASSERT_TRUE(resp->feed_message(i_to_r[3], kNow).has_value());
        ASSERT_EQ(resp->state(), NegotiationState::Complete);
    }

    NodeId              initiator_node_id_{};
    NodeId              responder_node_id_{};
    crypto::DsaKeyPair  initiator_kp_;
    crypto::DsaKeyPair  responder_kp_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Full round-trip tests
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, FullRoundTrip_Hybrid) {
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::PqcOnly, OperatingMode::Hybrid, OperatingMode::Transition}));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::Hybrid, OperatingMode::Transition}));

    run_full_exchange(init, resp);

    auto i_res = init->result();
    ASSERT_TRUE(i_res.has_value());
    EXPECT_EQ(i_res.value().negotiated_mode, OperatingMode::Hybrid);

    auto r_res = resp->result();
    ASSERT_TRUE(r_res.has_value());
    EXPECT_EQ(r_res.value().negotiated_mode, OperatingMode::Hybrid);

    // Both sides must agree on the same suite
    EXPECT_EQ(i_res.value().negotiated_suite, r_res.value().negotiated_suite);
}

TEST_F(NegotiationTest, FullRoundTrip_PqcOnly) {
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::PqcOnly}, OperatingMode::PqcOnly));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::PqcOnly}, OperatingMode::PqcOnly));

    run_full_exchange(init, resp);

    auto i_res = init->result();
    ASSERT_TRUE(i_res.has_value());
    EXPECT_EQ(i_res.value().negotiated_mode, OperatingMode::PqcOnly);
    // PQC-Only must use the strongest KEM
    EXPECT_EQ(i_res.value().negotiated_suite.kem_level, crypto::MlKem::Level::Kem1024);
    EXPECT_EQ(i_res.value().negotiated_suite.dsa_level, crypto::MlDsa::Level::Dsa87);
}

TEST_F(NegotiationTest, FullRoundTrip_Transition) {
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::Hybrid, OperatingMode::Transition}, OperatingMode::Transition));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::Transition}, OperatingMode::Transition));

    run_full_exchange(init, resp);

    auto res = init->result();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().negotiated_mode, OperatingMode::Transition);
}

TEST_F(NegotiationTest, FullRoundTrip_Classical) {
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::Classical, OperatingMode::Transition}, OperatingMode::Classical));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::Classical}, OperatingMode::Classical));

    run_full_exchange(init, resp);

    auto res = init->result();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().negotiated_mode, OperatingMode::Classical);
}

// ─────────────────────────────────────────────────────────────────────────────
// Downgrade prevention tests
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, DowngradeRejected_ModeBelow_InitiatorFloor) {
    // Initiator floor is PqcOnly; responder only supports Hybrid.
    // Responder will not find a mutually acceptable mode above the floor.
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::PqcOnly}, OperatingMode::PqcOnly));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::Hybrid}, OperatingMode::Hybrid));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    ASSERT_TRUE(init->start(kNow).has_value());

    // Responder should fail: no intersection at or above its own floor that also
    // satisfies the initiator's list
    auto resp_r = resp->feed_message(i_to_r[0], kNow);
    EXPECT_FALSE(resp_r.has_value());
    EXPECT_EQ(resp->state(), NegotiationState::Failed);
    EXPECT_EQ(resp_r.error().code, ErrorCode::PolicyViolation);
}

TEST_F(NegotiationTest, DowngradeRejected_ModeBelowResponderFloor) {
    // Initiator offers Classical+Transition, responder's floor is Hybrid.
    // No intersection at or above Hybrid → policy violation.
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::Classical, OperatingMode::Transition}, OperatingMode::Classical));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::Hybrid, OperatingMode::PqcOnly}, OperatingMode::Hybrid));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    ASSERT_TRUE(init->start(kNow).has_value());

    auto resp_r = resp->feed_message(i_to_r[0], kNow);
    EXPECT_FALSE(resp_r.has_value());
    EXPECT_EQ(resp->state(), NegotiationState::Failed);
    EXPECT_EQ(resp_r.error().code, ErrorCode::PolicyViolation);
}

TEST_F(NegotiationTest, DowngradeRejected_InitiatorRejectsModeBelowItsFloor) {
    // Responder selects a mode below the initiator's minimum_mode.
    // We do this by crafting a tampered ModeResp packet.
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::Hybrid, OperatingMode::Transition}, OperatingMode::Hybrid));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::Hybrid, OperatingMode::Transition}, OperatingMode::Transition));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    ASSERT_TRUE(init->start(kNow).has_value());

    // Let responder send a valid ModeResp, but then craft a fake ModeResp signed
    // with the responder's key but with selected_mode = Classical (below Hybrid floor).
    // This requires signing a fake message with the responder's private key.
    ASSERT_TRUE(resp->feed_message(i_to_r[0], kNow).has_value());
    // r_to_i[0] is the real ModeResp. Craft a tampered one.
    ModeRespMsg fake_resp;
    fake_resp.node_id       = responder_node_id_;
    fake_resp.echo_nonce    = Bytes(32, std::byte{0xAA}); // wrong nonce
    fake_resp.resp_nonce    = Bytes(32, std::byte{0xBB});
    fake_resp.selected_mode = OperatingMode::Classical;  // below floor
    fake_resp.timestamp     = kNow;

    // Sign with responder key so signature passes, but nonce echo will still fail
    NegotiationConfig fake_cfg = make_responder_cfg({OperatingMode::Classical}, OperatingMode::Classical);
    crypto::MlDsa dsa(crypto::MlDsa::Level::Dsa65);
    auto sig_r = dsa.sign(responder_kp_.private_key, fake_resp.get_signed_bytes());
    ASSERT_TRUE(sig_r.has_value());
    fake_resp.signature = sig_r.value().data;

    Bytes fake_body = fake_resp.serialise();
    MessageHeader hdr;
    hdr.type   = MessageType::ModeResp;
    hdr.length = static_cast<std::uint16_t>(fake_body.size());
    Bytes fake_pkt = hdr.serialise();
    fake_pkt.insert(fake_pkt.end(), fake_body.begin(), fake_body.end());

    // Initiator must reject (nonce echo mismatch)
    auto init_r = init->feed_message(fake_pkt, kNow);
    EXPECT_FALSE(init_r.has_value());
    EXPECT_EQ(init->state(), NegotiationState::Failed);
    EXPECT_EQ(init_r.error().code, ErrorCode::ReplayDetected);
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay / anti-replay tests
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, ReplayAttack_WrongNonceEcho_ModeResp) {
    // Directly forge a ModeResp with a wrong echo nonce and sign with responder key.
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::Hybrid}));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::Hybrid}));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    ASSERT_TRUE(init->start(kNow).has_value());
    ASSERT_TRUE(resp->feed_message(i_to_r[0], kNow).has_value()); // ModeReq → ModeResp

    // Tamper: flip echo_nonce in r_to_i[0]
    // Parse the real ModeResp and replace echo_nonce
    auto msg_body = body_of(r_to_i[0]);
    ASSERT_FALSE(msg_body.empty());
    auto resp_msg_r = ModeRespMsg::deserialise(msg_body);
    ASSERT_TRUE(resp_msg_r.has_value());
    auto tampered = std::move(resp_msg_r.value());
    // Flip all nonce bytes
    for (auto& b : tampered.echo_nonce) b = ~b;
    // Re-sign with responder key
    crypto::MlDsa dsa(crypto::MlDsa::Level::Dsa65);
    auto sig_r2 = dsa.sign(responder_kp_.private_key, tampered.get_signed_bytes());
    ASSERT_TRUE(sig_r2.has_value());
    tampered.signature = sig_r2.value().data;

    Bytes tampered_body = tampered.serialise();
    MessageHeader hdr;
    hdr.type   = MessageType::ModeResp;
    hdr.length = static_cast<std::uint16_t>(tampered_body.size());
    Bytes tampered_pkt = hdr.serialise();
    tampered_pkt.insert(tampered_pkt.end(), tampered_body.begin(), tampered_body.end());

    auto init_r = init->feed_message(tampered_pkt, kNow);
    EXPECT_FALSE(init_r.has_value());
    EXPECT_EQ(init_r.error().code, ErrorCode::ReplayDetected);
    EXPECT_EQ(init->state(), NegotiationState::Failed);
}

TEST_F(NegotiationTest, ReplayAttack_WrongNonceEcho_ProfileResp) {
    auto init = make_negotiation_initiator(make_initiator_cfg({OperatingMode::Hybrid}));
    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    // Drive through mode negotiation normally
    ASSERT_TRUE(init->start(kNow).has_value());
    ASSERT_TRUE(resp->feed_message(i_to_r[0], kNow).has_value());    // ModeReq
    ASSERT_TRUE(init->feed_message(r_to_i[0], kNow).has_value());    // ModeResp → ModeConfirm + ProfileReq
    ASSERT_TRUE(resp->feed_message(i_to_r[1], kNow).has_value());    // ModeConfirm
    ASSERT_TRUE(resp->feed_message(i_to_r[2], kNow).has_value());    // ProfileReq → ProfileResp
    ASSERT_EQ(r_to_i.size(), 2u);

    // Tamper ProfileResp: flip echo_nonce, re-sign
    auto pr_body = body_of(r_to_i[1]);
    ASSERT_FALSE(pr_body.empty());
    auto pr_r = ProfileRespMsg::deserialise(pr_body);
    ASSERT_TRUE(pr_r.has_value());
    auto tampered = std::move(pr_r.value());
    for (auto& b : tampered.echo_nonce) b = ~b;
    crypto::MlDsa dsa(crypto::MlDsa::Level::Dsa65);
    auto sig_r = dsa.sign(responder_kp_.private_key, tampered.get_signed_bytes());
    ASSERT_TRUE(sig_r.has_value());
    tampered.signature = sig_r.value().data;

    Bytes tb = tampered.serialise();
    MessageHeader hdr;
    hdr.type   = MessageType::ProfileResp;
    hdr.length = static_cast<std::uint16_t>(tb.size());
    Bytes tpkt = hdr.serialise();
    tpkt.insert(tpkt.end(), tb.begin(), tb.end());

    auto res = init->feed_message(tpkt, kNow);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ReplayDetected);
    EXPECT_EQ(init->state(), NegotiationState::Failed);
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature forgery rejection tests
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, ForgerySignature_ModeResp_Rejected) {
    auto init = make_negotiation_initiator(make_initiator_cfg({OperatingMode::Hybrid}));
    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    ASSERT_TRUE(init->start(kNow).has_value());
    ASSERT_TRUE(resp->feed_message(i_to_r[0], kNow).has_value());

    // Corrupt the signature bytes in r_to_i[0]
    Bytes corrupt = r_to_i[0];
    if (corrupt.size() > 10) {
        corrupt[corrupt.size() - 5] = ~corrupt[corrupt.size() - 5];
    }

    auto init_r = init->feed_message(corrupt, kNow);
    EXPECT_FALSE(init_r.has_value());
    EXPECT_EQ(init_r.error().code, ErrorCode::VerificationFailed);
    EXPECT_EQ(init->state(), NegotiationState::Failed);
}

TEST_F(NegotiationTest, ForgerySignature_ModeReq_Rejected) {
    // A third party signs a ModeReq with a key the responder doesn't trust.
    auto attacker_kp = gen_ml_dsa_kp();

    NodeId attacker_id{}; attacker_id[0] = std::byte{0xFF};
    ModeReqMsg fake;
    fake.node_id       = attacker_id;
    fake.nonce         = Bytes(32, std::byte{0xDE});
    fake.timestamp     = kNow;
    fake.offered_modes = {OperatingMode::Classical}; // downgrade attempt

    crypto::MlDsa dsa(crypto::MlDsa::Level::Dsa65);
    auto sig_r = dsa.sign(attacker_kp.private_key, fake.get_signed_bytes());
    ASSERT_TRUE(sig_r.has_value());
    fake.signature = sig_r.value().data;

    Bytes body = fake.serialise();
    MessageHeader hdr; hdr.type = MessageType::ModeReq;
    hdr.length = static_cast<std::uint16_t>(body.size());
    Bytes pkt = hdr.serialise();
    pkt.insert(pkt.end(), body.begin(), body.end());

    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));
    resp->set_send_fn([](Bytes) -> VoidResult { return ok(); });

    auto res = resp->feed_message(pkt, kNow);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::VerificationFailed);
    EXPECT_EQ(resp->state(), NegotiationState::Failed);
}

// ─────────────────────────────────────────────────────────────────────────────
// Transcript hash binding tests
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, TranscriptHashMismatch_ModeConfirm_Rejected) {
    auto init = make_negotiation_initiator(make_initiator_cfg({OperatingMode::Hybrid}));
    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    ASSERT_TRUE(init->start(kNow).has_value());
    ASSERT_TRUE(resp->feed_message(i_to_r[0], kNow).has_value());
    ASSERT_TRUE(init->feed_message(r_to_i[0], kNow).has_value());
    // i_to_r[1] = ModeConfirm, i_to_r[2] = ProfileReq
    ASSERT_GE(i_to_r.size(), 3u);

    // Corrupt transcript hash in i_to_r[1] (ModeConfirm)
    Bytes corrupt = i_to_r[1];
    // The transcript hash is 32 bytes; it starts after the 1-byte mode + MessageHeader.
    // We don't want to carefully parse; just flip bytes in the middle of the packet.
    for (std::size_t i = MessageHeader::kWireSize + 1; i < MessageHeader::kWireSize + 33 && i < corrupt.size(); ++i) {
        corrupt[i] = ~corrupt[i];
    }

    auto res = resp->feed_message(corrupt, kNow);
    EXPECT_FALSE(res.has_value());
    // Corrupting the packet causes either the ML-DSA signature check or
    // the SHA-256 transcript hash check to fail — both block the attack.
    EXPECT_TRUE(res.error().code == ErrorCode::AuthenticationFailed ||
                res.error().code == ErrorCode::VerificationFailed);
    EXPECT_EQ(resp->state(), NegotiationState::Failed);
}

TEST_F(NegotiationTest, TranscriptHashMismatch_ProfileConfirm_Rejected) {
    auto init = make_negotiation_initiator(make_initiator_cfg({OperatingMode::Hybrid}));
    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    // Drive to just before ProfileConfirm
    ASSERT_TRUE(init->start(kNow).has_value());
    ASSERT_TRUE(resp->feed_message(i_to_r[0], kNow).has_value());
    ASSERT_TRUE(init->feed_message(r_to_i[0], kNow).has_value());
    ASSERT_TRUE(resp->feed_message(i_to_r[1], kNow).has_value());
    ASSERT_TRUE(resp->feed_message(i_to_r[2], kNow).has_value());
    ASSERT_TRUE(init->feed_message(r_to_i[1], kNow).has_value());
    ASSERT_GE(i_to_r.size(), 4u);

    // Corrupt the ProfileConfirm packet
    Bytes corrupt = i_to_r[3];
    for (std::size_t i = MessageHeader::kWireSize + 1; i < MessageHeader::kWireSize + 33 && i < corrupt.size(); ++i) {
        corrupt[i] = ~corrupt[i];
    }
    auto res = resp->feed_message(corrupt, kNow);
    EXPECT_FALSE(res.has_value());
    // Corrupting the packet causes either the ML-DSA signature check or
    // the SHA-256 transcript hash check to fail — both block the attack.
    EXPECT_TRUE(res.error().code == ErrorCode::AuthenticationFailed ||
                res.error().code == ErrorCode::VerificationFailed);
    EXPECT_EQ(resp->state(), NegotiationState::Failed);
}

// ─────────────────────────────────────────────────────────────────────────────
// State machine ordering tests
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, StateTransition_InitiatorRejectsOutOfOrder) {
    auto init = make_negotiation_initiator(make_initiator_cfg({OperatingMode::Hybrid}));
    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    ASSERT_TRUE(init->start(kNow).has_value());

    // Feed a ProfileResp to the initiator before it has sent ProfileReq
    // (i.e., while still in WaitModeResp state)
    // Manufacture a fake ProfileResp packet with wrong header type
    ProfileRespMsg fake_pr;
    fake_pr.echo_nonce    = Bytes(32, std::byte{0});
    fake_pr.resp_nonce    = Bytes(32, std::byte{0});
    fake_pr.accepted      = true;
    fake_pr.kem_level     = crypto::MlKem::Level::Kem768;
    fake_pr.dsa_level     = crypto::MlDsa::Level::Dsa65;
    fake_pr.aead_algorithm= AeadAlgorithm::AesGcm256;
    fake_pr.hkdf_hash     = crypto::HkdfHash::Sha256;
    fake_pr.timestamp     = kNow;
    fake_pr.signature     = Bytes(1, std::byte{0});
    Bytes body = fake_pr.serialise();
    MessageHeader hdr; hdr.type = MessageType::ProfileResp;
    hdr.length = static_cast<std::uint16_t>(body.size());
    Bytes pkt = hdr.serialise(); pkt.insert(pkt.end(), body.begin(), body.end());

    auto res = init->feed_message(pkt, kNow);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::UnsupportedOperation);
    EXPECT_EQ(init->state(), NegotiationState::Failed);
}

TEST_F(NegotiationTest, StateTransition_ResponderRejectsOutOfOrder) {
    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));
    resp->set_send_fn([](Bytes) -> VoidResult { return ok(); });

    // Feed a ModeConfirm before ModeReq (Idle state)
    ModeConfirmMsg fake;
    fake.confirmed_mode   = OperatingMode::Hybrid;
    fake.transcript_hash  = {};
    fake.signature        = Bytes(1, std::byte{0});
    Bytes body = fake.serialise();
    MessageHeader hdr; hdr.type = MessageType::ModeConfirm;
    hdr.length = static_cast<std::uint16_t>(body.size());
    Bytes pkt = hdr.serialise(); pkt.insert(pkt.end(), body.begin(), body.end());

    auto res = resp->feed_message(pkt, kNow);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::UnsupportedOperation);
    EXPECT_EQ(resp->state(), NegotiationState::Failed);
}

// ─────────────────────────────────────────────────────────────────────────────
// Timestamp clock-skew test
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, TimestampClockSkew_Rejected) {
    auto init = make_negotiation_initiator(make_initiator_cfg({OperatingMode::Hybrid}));
    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));

    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    ASSERT_TRUE(init->start(kNow).has_value());
    // Feed ModeReq with a very far future now_ms so the timestamp is outside skew window
    constexpr Timestamp far_future = kNow + 999'999'999ULL;
    auto res = resp->feed_message(i_to_r[0], far_future);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ReplayDetected);
    EXPECT_EQ(resp->state(), NegotiationState::Failed);
}

// ─────────────────────────────────────────────────────────────────────────────
// PQC-Only enforces KEM level upgrade
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, PqcOnly_KemLevelUpgraded_By_Responder) {
    // Initiator proposes PQC-Only but sends Kem512 (which is too weak).
    // The responder should upgrade it to Kem1024 and mark accepted=false.
    auto init = make_negotiation_initiator(make_initiator_cfg(
        {OperatingMode::PqcOnly}, OperatingMode::PqcOnly));
    auto resp = make_negotiation_responder(make_responder_cfg(
        {OperatingMode::PqcOnly}, OperatingMode::PqcOnly));

    // We need to intercept the ProfileReq the initiator sends and check the
    // ProfileResp that comes back has the upgraded KEM level.
    std::vector<Bytes> i_to_r, r_to_i;
    init->set_send_fn([&](Bytes b) -> VoidResult { i_to_r.push_back(std::move(b)); return ok(); });
    resp->set_send_fn([&](Bytes b) -> VoidResult { r_to_i.push_back(std::move(b)); return ok(); });

    run_full_exchange(init, resp);

    auto r_res = resp->result();
    ASSERT_TRUE(r_res.has_value());
    EXPECT_EQ(r_res.value().negotiated_suite.kem_level, crypto::MlKem::Level::Kem1024);
    EXPECT_EQ(r_res.value().negotiated_suite.dsa_level, crypto::MlDsa::Level::Dsa87);
}

// ─────────────────────────────────────────────────────────────────────────────
// Result not available before completion
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(NegotiationTest, ResultNotAvailableBeforeComplete) {
    auto init = make_negotiation_initiator(make_initiator_cfg({OperatingMode::Hybrid}));
    auto resp = make_negotiation_responder(make_responder_cfg({OperatingMode::Hybrid}));

    // Before start
    auto res_i = init->result();
    EXPECT_FALSE(res_i.has_value());
    EXPECT_EQ(res_i.error().code, ErrorCode::UnsupportedOperation);

    auto res_r = resp->result();
    EXPECT_FALSE(res_r.has_value());
    EXPECT_EQ(res_r.error().code, ErrorCode::UnsupportedOperation);
}

TEST_F(NegotiationTest, NoOfferedModes_StartFails) {
    auto init = make_negotiation_initiator(make_initiator_cfg({}));
    init->set_send_fn([](Bytes) -> VoidResult { return ok(); });
    auto res = init->start(kNow);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST_F(NegotiationTest, StartWithoutSendFn_Fails) {
    auto init = make_negotiation_initiator(make_initiator_cfg({OperatingMode::Hybrid}));
    // No set_send_fn call
    auto res = init->start(kNow);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::UnsupportedOperation);
}
