#pragma once
#include <string>
#include <vector>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <filesystem>
#include "nlohmann/json.hpp"

namespace uav_pqc::process_sim {

struct PathResolver {
    std::string home_dir = ".";
    std::string config_dir = "";
    std::string data_dir = "";
    std::string pki_dir = "";
    std::string log_dir = "";
    std::string runtime_dir = "";
    std::string results_dir = "";
    std::string download_dir = "";
    std::string uav_query_root = "";

    void resolve_paths(int argc, char* argv[], const nlohmann::json& config_json = nlohmann::json{}) {
        home_dir = ".";
        
        if (!config_json.empty() && config_json.contains("paths")) {
            auto j_paths = config_json["paths"];
            if (j_paths.contains("home")) home_dir = j_paths["home"].get<std::string>();
        }

        if (const char* env = std::getenv("AETHER_HOME")) {
            home_dir = env;
        }

        for (int i = 1; i < argc; ++i) {
            if (std::strcmp(argv[i], "--home") == 0 && i + 1 < argc) {
                home_dir = argv[i + 1];
            }
        }

        auto resolve_field = [&](const std::string& cli_flag, const char* env_var, const std::string& json_key, const std::string& fallback_rel) -> std::string {
            for (int i = 1; i < argc; ++i) {
                if (std::strcmp(argv[i], cli_flag.c_str()) == 0 && i + 1 < argc) {
                    return argv[i + 1];
                }
            }
            if (const char* env = std::getenv(env_var)) {
                return env;
            }
            if (!config_json.empty() && config_json.contains("paths")) {
                auto j_paths = config_json["paths"];
                if (j_paths.contains(json_key)) {
                    return j_paths[json_key].get<std::string>();
                }
            }
            return home_dir + fallback_rel;
        };

        config_dir = resolve_field("--config-dir", "AETHER_CONFIG_DIR", "config", "/config");
        data_dir = resolve_field("--data-dir", "AETHER_DATA_DIR", "data", "/data");
        pki_dir = resolve_field("--pki-dir", "AETHER_PKI_DIR", "pki", "/data/pki");
        log_dir = resolve_field("--log-dir", "AETHER_LOG_DIR", "logs", "/logs");
        runtime_dir = resolve_field("--runtime-dir", "AETHER_RUNTIME_DIR", "runtime", "/runtime");
        results_dir = resolve_field("--results-dir", "AETHER_RESULTS_DIR", "results", "/results");
        download_dir = resolve_field("--download-dir", "AETHER_DOWNLOAD_DIR", "downloads", "/downloads");
        uav_query_root = resolve_field("--query-root", "AETHER_UAV_QUERY_ROOT", "uav_query_root", "/uav_media");
    }
};

struct NodeConfig {
    std::string ca_ip = "127.0.0.1";
    uint16_t ca_port = 28000;
    std::string gcs_ip = "127.0.0.1";
    uint16_t gcs_port = 28001;
    std::string local_ip = "127.0.0.1";
    uint16_t local_port = 0; // if 0, defaults to GCS/CA/UAV standard port
    int node_id = 1;         // UAV Index
    std::string log_level = "info";
    std::string op_mode = "hybrid";
    std::string interface_name = "eth0";
    std::string config_path = "";
    std::string camera_device = ""; // Optional hardware camera device path (e.g. /dev/video0, 1)
    std::string uav_routes_str = ""; // Format: id:ip:port,id:ip:port...
    PathResolver paths;
};

inline std::string get_env_or_default(const char* name, const std::string& def) {
    const char* val = std::getenv(name);
    return val ? std::string(val) : def;
}

inline bool is_dir_writable(const std::string& path) {
    try {
        std::filesystem::path p(path);
        if (!std::filesystem::exists(p)) {
            return false;
        }
        std::string test_file = path + "/.write_test";
        std::ofstream f(test_file);
        if (!f.is_open()) return false;
        f.close();
        std::filesystem::remove(test_file);
        return true;
    } catch (...) {
        return false;
    }
}

inline void validate_and_create_directories(const NodeConfig& cfg, bool is_ca, bool is_gcs, bool is_uav) {
    try {
        if (!cfg.paths.log_dir.empty()) {
            std::filesystem::create_directories(cfg.paths.log_dir);
        }
        if (!cfg.paths.runtime_dir.empty()) {
            std::filesystem::create_directories(cfg.paths.runtime_dir);
            if (!is_dir_writable(cfg.paths.runtime_dir)) {
                std::cerr << "ERROR: AETHER_RUNTIME_DIR is not writable: " << cfg.paths.runtime_dir << std::endl;
                std::exit(1);
            }
        }
        if (!cfg.paths.results_dir.empty()) {
            std::filesystem::create_directories(cfg.paths.results_dir);
        }

        if (is_ca) {
            std::filesystem::create_directories(cfg.paths.pki_dir + "/issued");
            std::filesystem::create_directories(cfg.paths.pki_dir + "/revoked");
            std::filesystem::create_directories(cfg.paths.pki_dir + "/csr");
            std::filesystem::create_directories(cfg.paths.pki_dir + "/backups");
            if (!is_dir_writable(cfg.paths.pki_dir)) {
                std::cerr << "ERROR: AETHER_PKI_DIR is not writable: " << cfg.paths.pki_dir << std::endl;
                std::exit(1);
            }
        }

        if (is_gcs) {
            if (!cfg.paths.download_dir.empty()) {
                std::filesystem::create_directories(cfg.paths.download_dir);
                if (!is_dir_writable(cfg.paths.download_dir)) {
                    std::cerr << "ERROR: AETHER_DOWNLOAD_DIR is not writable: " << cfg.paths.download_dir << std::endl;
                    std::exit(1);
                }
            }
        }

        if (is_uav) {
            if (!cfg.paths.uav_query_root.empty()) {
                std::filesystem::create_directories(cfg.paths.uav_query_root);
                if (!is_dir_writable(cfg.paths.uav_query_root)) {
                    std::cerr << "ERROR: AETHER_UAV_QUERY_ROOT is not writable: " << cfg.paths.uav_query_root << std::endl;
                    std::exit(1);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "ERROR: Failed to validate/create required directories: " << e.what() << std::endl;
        std::exit(1);
    }
}

inline NodeConfig parse_args(int argc, char* argv[]) {
    NodeConfig cfg;
    
    // 1. Read environment variables first
    cfg.ca_ip = get_env_or_default("CA_IP", cfg.ca_ip);
    if (const char* p = std::getenv("CA_PORT")) cfg.ca_port = static_cast<uint16_t>(std::stoi(p));
    cfg.gcs_ip = get_env_or_default("GCS_IP", cfg.gcs_ip);
    if (const char* p = std::getenv("GCS_PORT")) cfg.gcs_port = static_cast<uint16_t>(std::stoi(p));
    cfg.local_ip = get_env_or_default("LOCAL_IP", cfg.local_ip);
    if (const char* p = std::getenv("LOCAL_PORT")) cfg.local_port = static_cast<uint16_t>(std::stoi(p));
    if (const char* p = std::getenv("UAV_ID")) cfg.node_id = std::stoi(p);
    cfg.log_level = get_env_or_default("LOG_LEVEL", cfg.log_level);
    cfg.op_mode = get_env_or_default("OP_MODE", cfg.op_mode);
    cfg.interface_name = get_env_or_default("INTERFACE_NAME", cfg.interface_name);
    cfg.camera_device = get_env_or_default("CAMERA_DEVICE", cfg.camera_device);
    cfg.uav_routes_str = get_env_or_default("UAV_ROUTES", cfg.uav_routes_str);
 
    // 2. Parse command line arguments to get --config first
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            cfg.config_path = argv[++i];
        }
    }
 
    nlohmann::json j;
    // 3. Load from JSON config file if present
    if (!cfg.config_path.empty()) {
        std::ifstream f(cfg.config_path);
        if (f.good()) {
            try {
                f >> j;
                if (j.contains("ca_ip")) cfg.ca_ip = j["ca_ip"].get<std::string>();
                if (j.contains("ca_port")) cfg.ca_port = j["ca_port"].get<uint16_t>();
                if (j.contains("gcs_ip")) cfg.gcs_ip = j["gcs_ip"].get<std::string>();
                if (j.contains("gcs_port")) cfg.gcs_port = j["gcs_port"].get<uint16_t>();
                if (j.contains("local_ip")) cfg.local_ip = j["local_ip"].get<std::string>();
                if (j.contains("local_port")) cfg.local_port = j["local_port"].get<uint16_t>();
                if (j.contains("node_id")) cfg.node_id = j["node_id"].get<int>();
                if (j.contains("log_level")) cfg.log_level = j["log_level"].get<std::string>();
                if (j.contains("op_mode")) cfg.op_mode = j["op_mode"].get<std::string>();
                if (j.contains("interface_name")) cfg.interface_name = j["interface_name"].get<std::string>();
                if (j.contains("uav_routes_str")) cfg.uav_routes_str = j["uav_routes_str"].get<std::string>();
            } catch (const std::exception& e) {
                std::cerr << "[Config] Warning: Failed to parse config file " << cfg.config_path << ": " << e.what() << std::endl;
            }
        } else {
            std::cerr << "[Config] Warning: Could not open config file " << cfg.config_path << std::endl;
        }
    }

    // 4. Resolve paths based on precedence (CLI > Env > Config JSON > Defaults)
    cfg.paths.resolve_paths(argc, argv, j);

    // 5. Parse command line arguments to override other fields
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--ca-ip") == 0 && i + 1 < argc) {
            cfg.ca_ip = argv[++i];
        } else if (std::strcmp(argv[i], "--ca-port") == 0 && i + 1 < argc) {
            cfg.ca_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--gcs-ip") == 0 && i + 1 < argc) {
            cfg.gcs_ip = argv[++i];
        } else if (std::strcmp(argv[i], "--gcs-port") == 0 && i + 1 < argc) {
            cfg.gcs_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
            cfg.local_ip = argv[++i];
        } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            cfg.local_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            cfg.node_id = std::stoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            cfg.log_level = argv[++i];
        } else if (std::strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            cfg.op_mode = argv[++i];
        } else if (std::strcmp(argv[i], "--interface") == 0 && i + 1 < argc) {
            cfg.interface_name = argv[++i];
        } else if ((std::strcmp(argv[i], "--camera-device") == 0 || std::strcmp(argv[i], "--camera") == 0) && i + 1 < argc) {
            cfg.camera_device = argv[++i];
        } else if (std::strcmp(argv[i], "--uav-routes") == 0 && i + 1 < argc) {
            cfg.uav_routes_str = argv[++i];
        }
    }

    return cfg;
}

} // namespace uav_pqc::process_sim
