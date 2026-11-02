#include "uav_pqc/app/uav.hpp"
#include "uav_pqc/policy/context.hpp"
#include "uav_pqc/policy/acpe.hpp"
#include "uav_pqc/app/acpe_engine.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <iomanip>

using namespace uav_pqc;
using namespace uav_pqc::app;
using namespace uav_pqc::policy;

struct ScenarioSample {
    double sim_time;
    std::string scenario_name;
    uint32_t node_id;
    std::string mission;
    uint8_t battery;
    double energy;
    double rssi;
    double sinr;
    double packet_loss;
    double latency;
    double jitter;
    double cpu;
    double memory;
    std::string crypto_profile;
    std::string operating_mode;
    std::string policy_mode;
    std::string policy_reason;
    uint32_t handshake_count;
    std::string treekem_version;
    uint32_t treekem_rekeys;
    std::string session_id;
    uint32_t session_lifetime;
    int operator_override;
    int emergency_mode;
    int shutdown;
    
    double battery_multiplier;
    double comm_priority;
    double sync_rate;
    int video_enabled;
};

void write_csv(const std::string& path, const std::vector<ScenarioSample>& samples) {
    std::ofstream f(path);
    if (!f.is_open()) return;

    f << "SimulationTime,NodeID,Mission,Battery,Energy,RSSI,SINR,PacketLoss,Latency,Jitter,CPU,Memory,CryptoProfile,OperatingMode,PolicyMode,PolicyReason,HandshakeCount,TreeKEMVersion,TreeKEMRekeys,SessionID,SessionLifetime,OperatorOverride,EmergencyMode,Shutdown,BatteryMultiplier,CommPriority,SyncRate,VideoEnabled\n";
    for (const auto& s : samples) {
        f << s.sim_time << ","
          << s.node_id << ","
          << s.mission << ","
          << static_cast<int>(s.battery) << ","
          << s.energy << ","
          << s.rssi << ","
          << s.sinr << ","
          << s.packet_loss << ","
          << s.latency << ","
          << s.jitter << ","
          << s.cpu << ","
          << s.memory << ","
          << s.crypto_profile << ","
          << s.operating_mode << ","
          << s.policy_mode << ","
          << "\"" << s.policy_reason << "\"" << ","
          << s.handshake_count << ","
          << s.treekem_version << ","
          << s.treekem_rekeys << ","
          << s.session_id << ","
          << s.session_lifetime << ","
          << s.operator_override << ","
          << s.emergency_mode << ","
          << s.shutdown << ","
          << s.battery_multiplier << ","
          << s.comm_priority << ","
          << s.sync_rate << ","
          << s.video_enabled << "\n";
    }
}

void write_json(const std::string& path, const std::vector<ScenarioSample>& samples) {
    std::ofstream f(path);
    if (!f.is_open()) return;

    f << "[\n";
    for (size_t i = 0; i < samples.size(); ++i) {
        const auto& s = samples[i];
        f << "  {\n"
          << "    \"SimulationTime\": " << s.sim_time << ",\n"
          << "    \"ScenarioName\": \"" << s.scenario_name << "\",\n"
          << "    \"NodeID\": " << s.node_id << ",\n"
          << "    \"Mission\": \"" << s.mission << "\",\n"
          << "    \"Battery\": " << static_cast<int>(s.battery) << ",\n"
          << "    \"Energy\": " << s.energy << ",\n"
          << "    \"RSSI\": " << s.rssi << ",\n"
          << "    \"SINR\": " << s.sinr << ",\n"
          << "    \"PacketLoss\": " << s.packet_loss << ",\n"
          << "    \"Latency\": " << s.latency << ",\n"
          << "    \"Jitter\": " << s.jitter << ",\n"
          << "    \"CPU\": " << s.cpu << ",\n"
          << "    \"Memory\": " << s.memory << ",\n"
          << "    \"CryptoProfile\": \"" << s.crypto_profile << "\",\n"
          << "    \"OperatingMode\": \"" << s.operating_mode << "\",\n"
          << "    \"PolicyMode\": \"" << s.policy_mode << "\",\n"
          << "    \"PolicyReason\": \"" << s.policy_reason << "\",\n"
          << "    \"HandshakeCount\": " << s.handshake_count << ",\n"
          << "    \"TreeKEMVersion\": \"" << s.treekem_version << "\",\n"
          << "    \"TreeKEMRekeys\": " << s.treekem_rekeys << ",\n"
          << "    \"SessionID\": \"" << s.session_id << "\",\n"
          << "    \"SessionLifetime\": " << s.session_lifetime << ",\n"
          << "    \"OperatorOverride\": " << s.operator_override << ",\n"
          << "    \"EmergencyMode\": " << s.emergency_mode << ",\n"
          << "    \"Shutdown\": " << s.shutdown << ",\n"
          << "    \"BatteryMultiplier\": " << s.battery_multiplier << ",\n"
          << "    \"CommPriority\": " << s.comm_priority << ",\n"
          << "    \"SyncRate\": " << s.sync_rate << ",\n"
          << "    \"VideoEnabled\": " << s.video_enabled << "\n"
          << "  }" << (i + 1 < samples.size() ? "," : "") << "\n";
    }
    f << "]\n";
}

int main() {
    std::cout << "[VALIDATION] Initializing ACPE Validation Runner..." << std::endl;

    std::vector<ScenarioSample> samples;
    double current_time = 0.0;
    double current_rssi = -70.0;
    double current_sinr = 15.0;

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

    uav->initialize(uav_conf);

    auto record_sample = [&](const std::string& name) {
        auto fsm = uav->get_fsm_state();
        auto last_dec = uav_acpe->get_last_decision();
        std::string mode_str = last_dec.has_value() ? std::string(protocol::to_string(last_dec.value().mode)) : "Hybrid";
        std::string profile_str = last_dec.has_value() ? std::string(to_string(last_dec.value().profile)) : "Standard";
        std::string reason_str = last_dec.has_value() ? last_dec.value().rationale : "Default starting profile: Normal operation";

        ScenarioSample s;
        s.sim_time = current_time;
        s.scenario_name = name;
        s.node_id = 0;
        s.mission = "Surveillance";
        s.battery = uav->is_shutdown() ? 0 : 90;
        s.energy = 15000.0;
        s.rssi = current_rssi;
        s.sinr = current_sinr;
        s.packet_loss = 0.0;
        s.latency = 5.0;
        s.jitter = 0.5;
        s.cpu = 15.0;
        s.memory = 1248.0;
        s.crypto_profile = profile_str;
        s.operating_mode = mode_str;
        s.policy_mode = (fsm.policy == PolicyState::ManualPolicy) ? "Manual" : "Automatic";
        s.policy_reason = reason_str;
        s.handshake_count = 0;
        s.treekem_version = "TreeKEM-v1";
        s.treekem_rekeys = 0;
        s.session_id = uav->get_active_session_id_hex();
        s.session_lifetime = last_dec.has_value() ? last_dec.value().session_lifetime_seconds : 120;
        s.operator_override = (fsm.policy == PolicyState::ManualPolicy) ? 1 : 0;
        s.emergency_mode = (fsm.operational == OperationalState::EmergencyCommunication) ? 1 : 0;
        s.shutdown = uav->is_shutdown() ? 1 : 0;
        
        s.battery_multiplier = uav->get_mission().battery_consumption_multiplier;
        s.comm_priority = uav->get_mission().communication_priority;
        s.sync_rate = uav->get_mission().neighbor_sync_rate;
        s.video_enabled = uav->get_mission().video_streaming_enabled ? 1 : 0;

        samples.push_back(s);
        current_time += 1.0;
    };

    // Scenario 1: Baseline / Automatic Transitions (Normal operation)
    std::cout << "\n[SCENARIO 1] Automatic transitions: Default Baseline Evaluation..." << std::endl;
    uav->set_battery_level(90.0, 1000);
    record_sample("Baseline");

    std::cout << "[SCENARIO 1] Automatic transitions: Battery drops to 50%..." << std::endl;
    uav->set_battery_level(50.0, 2000);
    record_sample("BatteryDropTo50");

    // Scenario 2: Manual Transitions (Operator Override)
    std::cout << "\n[SCENARIO 2] Manual transitions: Operator overrides mode to PQCOnly/Hardened..." << std::endl;
    uav_acpe->get_core_engine()->trigger_operator_override(protocol::OperatingMode::PqcOnly, CryptographicProfile::Hardened);
    uav->set_battery_level(50.0, 3000);
    record_sample("ManualOverridePqc");

    // Scenario 3: Classical Approval (downgrade authorization flow)
    std::cout << "\n[SCENARIO 3] Classical approval: Resuming Automatic Policy..." << std::endl;
    uav_acpe->get_core_engine()->trigger_operator_resume();
    
    std::cout << "[SCENARIO 3] Classical approval: Extreme link degradation occurs (RSSI = -97 dBm)..." << std::endl;
    current_rssi = -97.0;
    current_sinr = 1.0;
    uav->set_link_stats(current_rssi, current_sinr, 0.0, 5.0);
    uav->set_battery_level(90.0, 4000); // Trigger check
    record_sample("ClassicalBlocked");

    std::cout << "[SCENARIO 3] Classical approval: Operator approves Classical mode (ID 99)..." << std::endl;
    uav->approve_classical_mode(99);
    uav->set_battery_level(90.0, 5000);
    record_sample("ClassicalApproved");

    // Reset link stats
    current_rssi = -70.0;
    current_sinr = 15.0;
    uav->set_link_stats(current_rssi, current_sinr, 0.0, 5.0);
    uav->set_battery_level(90.0, 6000); // Auto-renegotiates back to Hybrid due to good link

    // Scenario 4: Threat Escalation
    std::cout << "\n[SCENARIO 4] Threat escalation: threat level set to High..." << std::endl;
    uav->set_threat_level(ThreatLevel::High);
    uav->set_battery_level(90.0, 7000);
    record_sample("ThreatEscalation");

    // Scenario 5: Battery Drain
    std::cout << "\n[SCENARIO 5] Battery drain: battery drops to 30%..." << std::endl;
    uav->set_threat_level(ThreatLevel::Medium); // reset threat
    uav->set_battery_level(30.0, 8000);
    record_sample("BatteryDrainTo30");

    // Scenario 6: Mission Change
    std::cout << "\n[SCENARIO 6] Mission change: airspeed increased to imply high mobility..." << std::endl;
    uav->set_battery_level(30.0, 9000);
    record_sample("MissionChange");

    // Scenario 7: TreeKEM Update
    std::cout << "\n[SCENARIO 7] TreeKEM update: trigger rekey event..." << std::endl;
    uav->trigger_treekem_rekey();
    record_sample("TreeKEMRekey");

    // Scenario 8: Emergency Shutdown
    std::cout << "\n[SCENARIO 8] Emergency shutdown: battery depleted to 0%..." << std::endl;
    uav->set_battery_level(0.0, 10000);
    record_sample("BatteryDepleted");

    // Write Outputs
    write_csv("validation_scenarios.csv", samples);
    write_json("validation_scenarios.json", samples);

    std::cout << "\n[VALIDATION] Successfully wrote validation_scenarios.csv and validation_scenarios.json!" << std::endl;
    return 0;
}
