// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/configuration_manager.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

namespace uav_pqc::app {

namespace {

protocol::OperatingMode parse_mode(const std::string& s) {
    if (s == "hybrid") return protocol::OperatingMode::Hybrid;
    if (s == "transition") return protocol::OperatingMode::Transition;
    if (s == "pqc-only") return protocol::OperatingMode::PqcOnly;
    return protocol::OperatingMode::Classical;
}

policy::CryptographicProfile parse_profile(const std::string& s) {
    if (s == "lightweight") return policy::CryptographicProfile::Lightweight;
    if (s == "hardened") return policy::CryptographicProfile::Hardened;
    return policy::CryptographicProfile::Standard;
}

} // namespace

Result<AppConfig> ConfigurationManager::load_from_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        return err<AppConfig>(ErrorCode::InvalidArgument, "Failed to open configuration file: " + path);
    }
    std::stringstream buffer;
    buffer << f.rdbuf();
    return load_from_string(buffer.str());
}

Result<AppConfig> ConfigurationManager::load_from_string(const std::string& json_str) {
    try {
        auto j = nlohmann::json::parse(json_str);
        AppConfig cfg;

        if (j.contains("node_id")) {
            auto nid_hex = j["node_id"].get<std::string>();
            if (nid_hex.size() == 64) { // 32 bytes hex
                for (std::size_t i = 0; i < 32; ++i) {
                    std::string byte_str = nid_hex.substr(i * 2, 2);
                    cfg.our_node_id[i] = static_cast<std::byte>(std::stoul(byte_str, nullptr, 16));
                }
            }
        }

        if (j.contains("offered_modes")) {
            cfg.offered_modes.clear();
            for (const auto& item : j["offered_modes"]) {
                cfg.offered_modes.push_back(parse_mode(item.get<std::string>()));
            }
        } else {
            cfg.offered_modes = {protocol::OperatingMode::Hybrid};
        }

        if (j.contains("initial_profile")) {
            cfg.initial_profile = parse_profile(j["initial_profile"].get<std::string>());
        }

        if (j.contains("rekey_interval_seconds")) {
            cfg.rekey_interval_seconds = j["rekey_interval_seconds"].get<std::uint32_t>();
        }

        if (j.contains("ca_cert_path")) {
            cfg.ca_cert_path = j["ca_cert_path"].get<std::string>();
        }
        if (j.contains("our_cert_path")) {
            cfg.our_cert_path = j["our_cert_path"].get<std::string>();
        }
        if (j.contains("our_private_key_path")) {
            cfg.our_private_key_path = j["our_private_key_path"].get<std::string>();
        }
        if (j.contains("gcs_address")) {
            cfg.gcs_address = j["gcs_address"].get<std::string>();
        }
        if (j.contains("gcs_port")) {
            cfg.gcs_port = j["gcs_port"].get<std::uint16_t>();
        }
        if (j.contains("local_port")) {
            cfg.local_port = j["local_port"].get<std::uint16_t>();
        }

        if (j.contains("battery_threshold_lightweight")) {
            cfg.battery_threshold_lightweight = j["battery_threshold_lightweight"].get<double>();
        }
        if (j.contains("battery_threshold_standard")) {
            cfg.battery_threshold_standard = j["battery_threshold_standard"].get<double>();
        }
        if (j.contains("acpe_rules_path")) {
            cfg.acpe_rules_path = j["acpe_rules_path"].get<std::string>();
        }
        if (j.contains("initial_mission_criticality")) {
            cfg.initial_mission_criticality = j["initial_mission_criticality"].get<double>();
        }
        if (j.contains("initial_network_congestion")) {
            cfg.initial_network_congestion = j["initial_network_congestion"].get<double>();
        }
        if (j.contains("initial_swarm_density")) {
            cfg.initial_swarm_density = j["initial_swarm_density"].get<double>();
        }
        if (j.contains("initial_cpu_utilization")) {
            cfg.initial_cpu_utilization = j["initial_cpu_utilization"].get<double>();
        }
        if (j.contains("security_downgrade_threshold")) {
            cfg.security_downgrade_threshold = j["security_downgrade_threshold"].get<double>();
        }

        if (j.contains("crypto_profiles")) {
            const auto& cp = j["crypto_profiles"];
            if (cp.contains("lightweight")) {
                std::string str = cp["lightweight"].dump();
                auto p_r = policy::ProfileParameters::from_json(
                    ByteSpan{reinterpret_cast<const std::byte*>(str.data()), str.size()});
                if (p_r) {
                    cfg.lightweight_profile = std::move(p_r.value());
                }
            }
            if (cp.contains("standard")) {
                std::string str = cp["standard"].dump();
                auto p_r = policy::ProfileParameters::from_json(
                    ByteSpan{reinterpret_cast<const std::byte*>(str.data()), str.size()});
                if (p_r) {
                    cfg.standard_profile = std::move(p_r.value());
                }
            }
            if (cp.contains("hardened")) {
                std::string str = cp["hardened"].dump();
                auto p_r = policy::ProfileParameters::from_json(
                    ByteSpan{reinterpret_cast<const std::byte*>(str.data()), str.size()});
                if (p_r) {
                    cfg.hardened_profile = std::move(p_r.value());
                }
            }
        }

        config_ = cfg;
        return ok<AppConfig>(cfg);
    } catch (const std::exception& e) {
        return err<AppConfig>(ErrorCode::InvalidArgument, std::string("JSON configuration parsing failed: ") + e.what());
    }
}

} // namespace uav_pqc::app
