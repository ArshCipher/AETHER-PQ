// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/app/logger.hpp"
#include "uav_pqc/app/event_bus.hpp"
#include "uav_pqc/app/configuration_manager.hpp"
#include "uav_pqc/app/crypto_manager.hpp"
#include "uav_pqc/app/network_manager.hpp"
#include "uav_pqc/app/session_manager.hpp"
#include "uav_pqc/app/acpe_engine.hpp"
#include "uav_pqc/app/treekem_controller.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/app/uav.hpp"
#include "uav_pqc/app/ground_control_station.hpp"
#include "uav_pqc/app/swarm.hpp"

using namespace uav_pqc;
using namespace uav_pqc::app;

namespace {

struct TestEvent {
    int value;
};

const std::string kMockConfig = R"({
    "node_id": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "offered_modes": ["hybrid", "pqc-only"],
    "initial_profile": "standard",
    "rekey_interval_seconds": 60,
    "battery_threshold_lightweight": 15.0,
    "battery_threshold_standard": 40.0
})";

} // namespace

TEST(AppArchitectureTest, LoggerTest) {
    Logger logger(LogLevel::Debug);
    logger.log(LogLevel::Info, "test_context", "Hello from architecture logger!");
    logger.set_level(LogLevel::Warn);
    logger.flush();
}

TEST(AppArchitectureTest, EventBusTest) {
    auto bus = std::make_shared<EventBus>();
    int received_val = 0;
    
    bus->subscribe<TestEvent>([&](const TestEvent& ev) {
        received_val = ev.value;
    });

    bus->publish(TestEvent{42});
    EXPECT_EQ(received_val, 42);
}

TEST(AppArchitectureTest, ConfigurationManagerTest) {
    ConfigurationManager mgr;
    auto res = mgr.load_from_string(kMockConfig);
    ASSERT_TRUE(res.has_value());
    
    const auto& cfg = mgr.get_config();
    EXPECT_EQ(cfg.rekey_interval_seconds, 60);
    EXPECT_EQ(cfg.battery_threshold_lightweight, 15.0);
    EXPECT_EQ(cfg.battery_threshold_standard, 40.0);
}

TEST(AppArchitectureTest, ConfigurationManagerCryptoProfilesTest) {
    ConfigurationManager mgr;
    const std::string cp_config = R"({
        "crypto_profiles": {
            "standard": {
                "kem_level": "ml-kem-1024",
                "preferred_aead": "chacha20-poly1305",
                "rekey_interval_seconds": 999
            }
        }
    })";
    auto res = mgr.load_from_string(cp_config);
    ASSERT_TRUE(res.has_value());
    const auto& cfg = mgr.get_config();
    EXPECT_EQ(cfg.standard_profile.kem_level, crypto::MlKem::Level::Kem1024);
    EXPECT_EQ(cfg.standard_profile.preferred_aead, protocol::AeadAlgorithm::ChaCha20Poly);
    EXPECT_EQ(cfg.standard_profile.rekey_interval_seconds, 999);
}

TEST(AppArchitectureTest, CryptoManagerTest) {
    CryptoManager crypto;
    auto kem_kp_r = crypto.generate_kem_keypair();
    ASSERT_TRUE(kem_kp_r.has_value());

    auto dsa_kp_r = crypto.generate_dsa_keypair();
    ASSERT_TRUE(dsa_kp_r.has_value());

    crypto.set_static_dsa_keypair(std::move(dsa_kp_r.value()));
    Bytes transcript = {std::byte{1}, std::byte{2}, std::byte{3}};
    
    auto sig_r = crypto.sign_transcript(transcript);
    ASSERT_TRUE(sig_r.has_value());

    const auto& kp_ref = crypto.get_static_dsa_keypair();
    ASSERT_TRUE(kp_ref.has_value());
    auto verify_r = crypto.verify_transcript(transcript, sig_r.value(), kp_ref->public_key);
    ASSERT_TRUE(verify_r.has_value());
    EXPECT_TRUE(verify_r.value());

    // 1. Random Number Generation
    auto rand_r = crypto.generate_random_bytes(16);
    ASSERT_TRUE(rand_r.has_value());
    EXPECT_EQ(rand_r.value().size(), 16u);

    // 2. AES-GCM (128 and 256)
    Bytes pt = {std::byte{'H'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
    Bytes key256(32, std::byte{0x01});
    Bytes iv(12, std::byte{0x02});
    Bytes aad = {std::byte{0x03}};

    auto enc_aes = crypto.aes_gcm_encrypt(pt, key256, iv, aad);
    ASSERT_TRUE(enc_aes.has_value());

    auto dec_aes = crypto.aes_gcm_decrypt(enc_aes.value(), key256, iv, aad);
    ASSERT_TRUE(dec_aes.has_value());
    EXPECT_EQ(dec_aes.value(), pt);

    // 3. ChaCha20-Poly1305
    auto enc_chacha = crypto.chacha20_poly1305_encrypt(pt, key256, iv, aad);
    ASSERT_TRUE(enc_chacha.has_value());

    auto dec_chacha = crypto.chacha20_poly1305_decrypt(enc_chacha.value(), key256, iv, aad);
    ASSERT_TRUE(dec_chacha.has_value());
    EXPECT_EQ(dec_chacha.value(), pt);

    // 4. HKDF-SHA256
    auto prk_r = crypto.hkdf_sha256_extract_and_expand(iv, pt, aad, 32);
    ASSERT_TRUE(prk_r.has_value());
    EXPECT_EQ(prk_r.value().size(), 32u);

    // 5. PEM Serialization
    auto ecdsa_kp_r = crypto.generate_ecdsa_p256_keypair();
    ASSERT_TRUE(ecdsa_kp_r.has_value());

    auto pem_priv_r = crypto.export_dsa_private_key_to_pem(ecdsa_kp_r.value().private_key, true);
    ASSERT_TRUE(pem_priv_r.has_value());
    EXPECT_TRUE(pem_priv_r.value().find("-----BEGIN EC PRIVATE KEY-----") != std::string::npos);

    auto pem_pub_r = crypto.export_dsa_public_key_to_pem(ecdsa_kp_r.value().public_key, true);
    ASSERT_TRUE(pem_pub_r.has_value());
    EXPECT_TRUE(pem_pub_r.value().find("-----BEGIN PUBLIC KEY-----") != std::string::npos);

    auto imported_kp_r = crypto.import_dsa_keypair_from_pem(pem_priv_r.value(), pem_pub_r.value(), true);
    ASSERT_TRUE(imported_kp_r.has_value());
    EXPECT_EQ(imported_kp_r.value().public_key.data, ecdsa_kp_r.value().public_key.data);

    // 6. Zeroization
    Bytes sensitive = {std::byte{0xAA}, std::byte{0xBB}};
    crypto.clean_sensitive_memory(sensitive);
    EXPECT_EQ(sensitive[0], std::byte{0});
    EXPECT_EQ(sensitive[1], std::byte{0});
}

TEST(AppArchitectureTest, CertificateAuthorityTest) {
    CryptoManager crypto;
    auto dsa_kp_r = crypto.generate_dsa_keypair();
    ASSERT_TRUE(dsa_kp_r.has_value());

    NodeId ca_id{};
    ca_id[0] = std::byte{0xCA};
    CertificateAuthority ca(ca_id, std::move(dsa_kp_r.value()));

    NodeId uav_id{};
    uav_id[0] = std::byte{0x0A};

    // Construct mock public keys
    crypto::DsaPublicKey mock_ecdsa_pk;
    mock_ecdsa_pk.data.resize(65, std::byte{0xAA});
    crypto::DsaPublicKey mock_mldsa_pk;
    mock_mldsa_pk.data.resize(1952, std::byte{0xBB});

    auto cert_r = ca.issue_certificate("UAV_01", uav_id, mock_ecdsa_pk, mock_mldsa_pk, 3600000, 1000);
    ASSERT_TRUE(cert_r.has_value());
    EXPECT_EQ(cert_r.value().subject_name(), "UAV_01");
}

TEST(AppArchitectureTest, NetworkAndSessionManagerTest) {
    auto tx_fn = [](const Bytes&) -> VoidResult {
        return ok();
    };

    NetworkManager net(tx_fn, 500);
    SessionManager session_mgr;

    // Verify basic set/get group broadcast key
    SecureBytes kb(32);
    std::fill_n(kb.data(), 32, std::byte{0xCC});
    group::GroupKey gk(1, std::move(kb), protocol::AeadAlgorithm::AesGcm256, 0, 3600000);
    session_mgr.set_group_key(std::move(gk));

    Bytes plaintext = {std::byte{0xAA}, std::byte{0xBB}};
    Bytes aad = {std::byte{0x01}};
    
    auto enc_r = session_mgr.encrypt_group_broadcast(plaintext, aad, 1);
    ASSERT_TRUE(enc_r.has_value());

    auto dec_r = session_mgr.decrypt_group_broadcast(enc_r.value(), aad, 1);
    ASSERT_TRUE(dec_r.has_value());
    EXPECT_EQ(dec_r.value(), plaintext);
}

TEST(AppArchitectureTest, AcpeEngineTest) {
    AcpeEngine acpe;
    policy::PolicyContext ctx;
    ctx.battery_percent = 10; // trigger lightweight
    ctx.hardware_class = policy::HardwareClass::EmbeddedLinux;
    ctx.threat_level = policy::ThreatLevel::Low;

    bool triggered = false;
    acpe.register_policy_handler([&](const policy::AcpeDecision&) {
        triggered = true;
    });

    auto dec_r = acpe.evaluate_context(ctx);
    ASSERT_TRUE(dec_r.has_value());
    EXPECT_EQ(dec_r.value().profile, policy::CryptographicProfile::Lightweight);
}

TEST(AppArchitectureTest, TreeKemControllerTest) {
    protocol::CipherSuite suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    TreeKemController ctrl(suite);

    NodeId uav_id{};
    uav_id[0] = std::byte{0x01};

    crypto::MlKem mlkem(crypto::MlKem::Level::Kem768);
    auto kp_r = mlkem.generate_keypair();
    ASSERT_TRUE(kp_r.has_value());

    group::SwarmMember member{
        .node_id = uav_id,
        .leaf_key = kp_r.value().public_key,
        .leaf_index = 0,
        .joined_at_ms = 0
    };

    auto reg_r = ctrl.register_member(member);
    ASSERT_TRUE(reg_r.has_value());
    EXPECT_EQ(ctrl.get_epoch(), 1);
}

TEST(AppArchitectureTest, SwarmMutualVerificationTest) {
    auto bus = std::make_shared<EventBus>();
    
    // We construct GCS managers
    auto gcs_config_mgr = std::make_shared<ConfigurationManager>();
    auto gcs_crypto_mgr = std::make_shared<CryptoManager>();
    auto gcs_session_mgr = std::make_shared<SessionManager>();
    auto gcs_acpe = std::make_shared<AcpeEngine>();
    protocol::CipherSuite suite = protocol::CipherSuite::make_hybrid(protocol::AeadAlgorithm::AesGcm256);
    auto gcs_treekem = std::make_shared<TreeKemController>(suite);

    // We construct UAV managers
    auto uav_config_mgr = std::make_shared<ConfigurationManager>();
    auto uav_crypto_mgr = std::make_shared<CryptoManager>();
    auto uav_session_mgr = std::make_shared<SessionManager>();
    auto uav_acpe = std::make_shared<AcpeEngine>();

    auto swarm = std::make_shared<Swarm>();

    // Wire simulated GCS packet transmitter directly to swarm routing
    auto gcs_tx = [swarm](const Bytes& pkt) -> VoidResult {
        NodeId dst_uav{};
        dst_uav[0] = std::byte{0x0A}; // route to UAV_01
        return swarm->route_packet(dst_uav, pkt, 1000);
    };

    // Wire simulated UAV packet transmitter directly to swarm routing
    auto uav_tx = [swarm](const Bytes& pkt) -> VoidResult {
        NodeId dst_gcs{}; // GCS node id (defaults to all zeros)
        return swarm->route_packet(dst_gcs, pkt, 1000);
    };

    auto gcs_net = std::make_shared<NetworkManager>(gcs_tx, 500);
    auto uav_net = std::make_shared<NetworkManager>(uav_tx, 500);

    auto gcs = std::make_shared<GroundControlStation>(
        bus, gcs_config_mgr, gcs_crypto_mgr, gcs_net, gcs_session_mgr, gcs_acpe, gcs_treekem
    );

    auto uav = std::make_shared<Uav>(
        bus, uav_config_mgr, uav_crypto_mgr, uav_net, uav_session_mgr, uav_acpe
    );

    swarm->set_gcs(gcs);
    swarm->add_uav(uav);

    // Initialise nodes
    const std::string gcs_conf = R"({
        "node_id": "0000000000000000000000000000000000000000000000000000000000000000",
        "offered_modes": ["hybrid"]
    })";

    const std::string uav_conf = R"({
        "node_id": "0a00000000000000000000000000000000000000000000000000000000000000",
        "offered_modes": ["hybrid"]
    })";

    ASSERT_TRUE(gcs->initialize(gcs_conf).has_value());
    ASSERT_TRUE(uav->initialize(uav_conf).has_value());

    // Trigger battery profile changes
    uav->set_battery_level(12.0, 1000);
    
    // Enroll UAV with a real ML-KEM key
    crypto::MlKem mlkem(crypto::MlKem::Level::Kem768);
    auto kp_r = mlkem.generate_keypair();
    ASSERT_TRUE(kp_r.has_value());

    auto enroll_r = gcs->enroll_uav(uav->get_node_id(), kp_r.value().public_key);
    ASSERT_TRUE(enroll_r.has_value());
}

TEST(AppArchitectureTest, UavDynamicJsonConfigOverrides) {
    auto bus = std::make_shared<EventBus>();
    auto uav_config_mgr = std::make_shared<ConfigurationManager>();
    auto uav_crypto_mgr = std::make_shared<CryptoManager>();
    auto uav_session_mgr = std::make_shared<SessionManager>();
    auto uav_acpe = std::make_shared<AcpeEngine>();

    auto uav = std::make_shared<Uav>(
        bus, uav_config_mgr, uav_crypto_mgr, std::make_shared<NetworkManager>([](const Bytes&){ return ok(); }, 500), uav_session_mgr, uav_acpe
    );

    const std::string custom_uav_conf = R"({
        "node_id": "0a00000000000000000000000000000000000000000000000000000000000000",
        "offered_modes": ["hybrid"],
        "mission": "Surveillance",
        "battery_capacity": 20000.0,
        "speed": 18.0,
        "telemetry_interval_ms": 1500.0,
        "payload_size": 1200,
        "treekem_rekey_interval_sec": 45.0,
        "threat_level": "High",
        "p_hover": 280.0,
        "c_drag": 0.22
    })";

    ASSERT_TRUE(uav->initialize(custom_uav_conf).has_value());

    // Verify overrides succeeded and replaced Surveillance default mission coefficients
    EXPECT_DOUBLE_EQ(uav->get_remaining_energy_joules(), 20000.0);
    EXPECT_DOUBLE_EQ(uav->get_telemetry_interval_ms(), 1500.0);
    EXPECT_EQ(uav->get_payload_size(), 1200);
    EXPECT_DOUBLE_EQ(uav->get_treekem_rekey_interval_sec(), 45.0);

    // Call update_battery to verify that custom p_hover and c_drag are used for drain
    // At t=0 -> t=1.0s, speed = 10.0m/s
    uav->update_battery(1000, 10.0, 0.0); // establishes baseline
    uav->update_battery(2000, 10.0, 0.0); // dt = 1.0s

    // power = p_hover (280) + c_drag (0.22) * 10^3 (1000) = 280 + 220 = 500 Watts
    // energy consumed in 1.0s = 500 Joules
    // remaining energy should be 20000 - 500 = 19500 Joules
    EXPECT_NEAR(uav->get_remaining_energy_joules(), 19500.0, 5.0);
}

TEST(AppArchitectureTest, UavClassicalModeAuthorization) {
    auto bus = std::make_shared<EventBus>();
    auto uav_config_mgr = std::make_shared<ConfigurationManager>();
    auto uav_crypto_mgr = std::make_shared<CryptoManager>();
    auto uav_session_mgr = std::make_shared<SessionManager>();
    auto uav_acpe = std::make_shared<AcpeEngine>();

    auto uav = std::make_shared<Uav>(
        bus, uav_config_mgr, uav_crypto_mgr, std::make_shared<NetworkManager>([](const Bytes&){ return ok(); }, 500), uav_session_mgr, uav_acpe
    );

    const std::string uav_conf = R"({
        "node_id": "0a00000000000000000000000000000000000000000000000000000000000000",
        "offered_modes": ["hybrid"],
        "mission": "Surveillance",
        "battery_capacity": 15000.0,
        "security_downgrade_threshold": -95.0
    })";

    ASSERT_TRUE(uav->initialize(uav_conf).has_value());

    // 1. Initial State: Hybrid mode active
    EXPECT_FALSE(uav->is_waiting_for_classical_approval());
    EXPECT_FALSE(uav->is_classical_approved());

    // 2. Weak Channel -> RSSI = -83.0 dBm (Degraded but above SecurityDowngradeThreshold)
    // Progressive adaptation should switch profile to Lightweight but NOT recommend Classical Mode!
    uav->set_link_stats(-83.0, 3.8, 0.0, 5.0);
    uav->set_battery_level(90.0, 1000);

    EXPECT_FALSE(uav->is_waiting_for_classical_approval());
    EXPECT_FALSE(uav->is_classical_approved());

    // 3. Extreme degradation -> RSSI = -97.0 dBm (Below SecurityDowngradeThreshold -95.0 dBm)
    // Last-resort Classical recommendation should trigger!
    uav->set_link_stats(-97.0, 1.0, 0.0, 5.0);
    uav->set_battery_level(90.0, 2000);

    // Confirm that it generates a recommendation, waits for GCS, and blocks automatic downgrade
    EXPECT_TRUE(uav->is_waiting_for_classical_approval());
    EXPECT_FALSE(uav->is_classical_approved());
    EXPECT_NE(uav_config_mgr->get_config().offered_modes[0], protocol::OperatingMode::Classical); // Still Hybrid!

    // 4. Approve Classical Mode from Operator GCS decision (command 50001)
    uav->approve_classical_mode(99); // Operator ID 99

    // 5. Confirm that it transitions to Classical, clears wait state, and initiates handshake
    EXPECT_FALSE(uav->is_waiting_for_classical_approval());
    EXPECT_TRUE(uav->is_classical_approved());
    EXPECT_EQ(uav_config_mgr->get_config().offered_modes[0], protocol::OperatingMode::Classical);
}

TEST(AppArchitectureTest, UavAcpeExtendedDecisionPriority) {
    auto bus = std::make_shared<EventBus>();
    auto uav_config = std::make_shared<ConfigurationManager>();
    auto uav_crypto = std::make_shared<CryptoManager>();
    auto uav_session = std::make_shared<SessionManager>();
    auto acpe = std::make_shared<AcpeEngine>();

    policy::PolicyContext ctx;
    ctx.battery_percent = 90;
    ctx.hardware_class = policy::HardwareClass::EmbeddedLinux;
    ctx.threat_level = policy::ThreatLevel::Medium;
    ctx.mission_criticality = 5.0;

    // 1. Baseline Evaluation: Default Policy (Hybrid / Standard)
    auto res_base = acpe->evaluate_context(ctx);
    ASSERT_TRUE(res_base.has_value());
    EXPECT_EQ(res_base.value().mode, protocol::OperatingMode::Hybrid);
    EXPECT_EQ(res_base.value().profile, policy::CryptographicProfile::Standard);
    EXPECT_EQ(res_base.value().telemetry_interval_ms, 1000);

    // 2. High Resource Usage Priority: CPU utilization > 80%
    // Lower priority than battery shutdown, manual overrides, criticality, or threat,
    // but higher priority than default policy. Enforces Transition / Lightweight.
    ctx.cpu_utilization = 90.0;
    auto res_resources = acpe->evaluate_context(ctx);
    ASSERT_TRUE(res_resources.has_value());
    EXPECT_EQ(res_resources.value().mode, protocol::OperatingMode::Transition);
    EXPECT_EQ(res_resources.value().profile, policy::CryptographicProfile::Lightweight);

    // Reset CPU
    ctx.cpu_utilization = 0.0;

    // 3. Battery Degradation: Battery = 50%
    // Enforces Hybrid / Lightweight (telemetry default 1000ms)
    ctx.battery_percent = 50;
    auto res_battery = acpe->evaluate_context(ctx);
    ASSERT_TRUE(res_battery.has_value());
    EXPECT_EQ(res_battery.value().mode, protocol::OperatingMode::Hybrid);
    EXPECT_EQ(res_battery.value().profile, policy::CryptographicProfile::Lightweight);

    // 4. Mission Criticality Override (Priority 3 > Battery Tiers Priority 5):
    // Highly critical mission (criticality >= 8.0) overrides battery limits and forces Hardened profile + high rate telemetry!
    ctx.mission_criticality = 9.0;
    auto res_critical = acpe->evaluate_context(ctx);
    ASSERT_TRUE(res_critical.has_value());
    EXPECT_EQ(res_critical.value().mode, protocol::OperatingMode::Hybrid);
    EXPECT_EQ(res_critical.value().profile, policy::CryptographicProfile::Hardened);
    EXPECT_EQ(res_critical.value().telemetry_interval_ms, 500); // High rate!
}

TEST(AppArchitectureTest, UavDynamicMissionChangeReevaluation) {
    auto bus = std::make_shared<EventBus>();
    auto uav_config_mgr = std::make_shared<ConfigurationManager>();
    auto uav_crypto_mgr = std::make_shared<CryptoManager>();
    auto uav_session_mgr = std::make_shared<SessionManager>();
    auto uav_acpe = std::make_shared<AcpeEngine>();

    auto uav = std::make_shared<Uav>(
        bus, uav_config_mgr, uav_crypto_mgr, std::make_shared<NetworkManager>([](const Bytes&){ return ok(); }, 500), uav_session_mgr, uav_acpe
    );

    const std::string uav_conf = R"({
        "node_id": "0a00000000000000000000000000000000000000000000000000000000000000",
        "offered_modes": ["hybrid"],
        "mission": "Surveillance",
        "battery_capacity": 15000.0
    })";

    ASSERT_TRUE(uav->initialize(uav_conf).has_value());

    // Surveillance baseline defaults: Telemetry = 1000ms, Payload = 800
    EXPECT_EQ(uav->get_telemetry_interval_ms(), 1000.0);
    EXPECT_EQ(uav->get_payload_size(), 800);

    // Switch mission to Delivery
    UavMission delivery_mission;
    delivery_mission.type = UavMissionType::Delivery;
    delivery_mission.criticality = 3.0;
    delivery_mission.speed_m_s = 25.0;
    delivery_mission.target_altitude = 100.0;
    delivery_mission.default_operating_mode = protocol::OperatingMode::Transition;
    delivery_mission.default_crypto_profile = policy::CryptographicProfile::Lightweight;
    delivery_mission.telemetry_interval_sec = 5.0;
    delivery_mission.payload_size = 0;
    delivery_mission.preferred_cipher_suite = "MLKEM512-MLDSA44-AES128GCM";
    delivery_mission.treekem_rekey_interval_sec = 45.0;
    delivery_mission.session_lifetime_sec = 300;
    delivery_mission.battery_consumption_multiplier = 1.5;
    delivery_mission.communication_priority = 3.0;
    delivery_mission.neighbor_sync_rate = 0.2;
    delivery_mission.video_streaming_enabled = false;

    uav->set_mission(delivery_mission);

    // Should dynamically re-evaluate: Telemetry to 5000ms, Payload size to 0
    EXPECT_EQ(uav->get_telemetry_interval_ms(), 5000.0);
    EXPECT_EQ(uav->get_payload_size(), 0);

    // Switch mission to Search & Rescue (criticality = 9.0)
    UavMission sr_mission;
    sr_mission.type = UavMissionType::SearchRescue;
    sr_mission.criticality = 9.0;
    sr_mission.speed_m_s = 5.0;
    sr_mission.target_altitude = 30.0;
    sr_mission.default_operating_mode = protocol::OperatingMode::PqcOnly;
    sr_mission.default_crypto_profile = policy::CryptographicProfile::Hardened;
    sr_mission.telemetry_interval_sec = 0.5;
    sr_mission.payload_size = 400;
    sr_mission.preferred_cipher_suite = "MLKEM1024-MLDSA87-AES256GCM";
    sr_mission.treekem_rekey_interval_sec = 15.0;
    sr_mission.session_lifetime_sec = 240;
    sr_mission.battery_consumption_multiplier = 1.3;
    sr_mission.communication_priority = 9.0;
    sr_mission.neighbor_sync_rate = 2.0;
    sr_mission.video_streaming_enabled = true;

    uav->set_mission(sr_mission);

    // Should dynamically re-evaluate: Telemetry to 500ms, Payload size to 400
    EXPECT_EQ(uav->get_telemetry_interval_ms(), 500.0);
    EXPECT_EQ(uav->get_payload_size(), 400);
}



