// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/policy/profile.hpp"
#include "uav_pqc/protocol/mode.hpp"
#include "uav_pqc/common/types.hpp"

#include <string>
#include <vector>

namespace uav_pqc::app {

/**
 * @brief Configuration data structure.
 */
struct AppConfig {
    NodeId our_node_id{};
    std::vector<protocol::OperatingMode> offered_modes;
    policy::CryptographicProfile initial_profile = policy::CryptographicProfile::Standard;
    std::uint32_t rekey_interval_seconds = 300;
    std::string ca_cert_path;
    std::string our_cert_path;
    std::string our_private_key_path;
    std::string gcs_address = "127.0.0.1";
    std::uint16_t gcs_port = 8080;
    std::uint16_t local_port = 8081;

    // ACPE threshold defaults (used if no JSON rules file is provided)
    double battery_threshold_lightweight = 20.0;
    double battery_threshold_standard = 50.0;

    // Path to JSON rules file (optional); loaded into AcpeEngine at startup
    std::string acpe_rules_path;

    // Initial sensor defaults used to seed the first PolicyContext
    double initial_mission_criticality = 5.0;
    double initial_network_congestion  = 0.0;
    double initial_swarm_density       = 0.0;
    double initial_cpu_utilization     = 0.0;
    double security_downgrade_threshold = -95.0;

    // Runtime-configured crypto profiles
    policy::ProfileParameters lightweight_profile = policy::ProfileParameters::lightweight();
    policy::ProfileParameters standard_profile    = policy::ProfileParameters::standard();
    policy::ProfileParameters hardened_profile    = policy::ProfileParameters::hardened();
};

/**
 * @brief Abstract ConfigurationManager interface.
 */
class IConfigurationManager {
public:
    IConfigurationManager() = default;
    virtual ~IConfigurationManager() = default;

    IConfigurationManager(const IConfigurationManager&) = delete;
    IConfigurationManager& operator=(const IConfigurationManager&) = delete;
    IConfigurationManager(IConfigurationManager&&) noexcept = default;
    IConfigurationManager& operator=(IConfigurationManager&&) noexcept = default;

    virtual Result<AppConfig> load_from_file(const std::string& path) = 0;
    virtual Result<AppConfig> load_from_string(const std::string& json_str) = 0;
    virtual const AppConfig& get_config() const noexcept = 0;
};

/**
 * @brief Concrete JSON-based ConfigurationManager class.
 */
class ConfigurationManager final : public IConfigurationManager {
public:
    ConfigurationManager() = default;
    ~ConfigurationManager() override = default;

    Result<AppConfig> load_from_file(const std::string& path) override;
    Result<AppConfig> load_from_string(const std::string& json_str) override;
    const AppConfig& get_config() const noexcept override { return config_; }

private:
    AppConfig config_;
};

} // namespace uav_pqc::app
