# src/app/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

uav_pqc_add_library(
    NAME    uav_pqc_app
    SOURCES
        logger.cpp
        event_bus.cpp
        configuration_manager.cpp
        crypto_manager.cpp
        network_manager.cpp
        session_manager.cpp
        acpe_engine.cpp
        treekem_controller.cpp
        certificate_authority.cpp
        uav.cpp
        ground_control_station.cpp
        d2d_coordinator.cpp
        swarm.cpp
    PUBLIC_LINKS
        uav_pqc_common
        uav_pqc_crypto
        uav_pqc_protocol
        uav_pqc_policy
        uav_pqc_group
        uav_pqc_transport
        uav_pqc_identity
        uav_pqc_session
        uav_pqc_platform
        $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_app EXPORT uav_pqc_targets)
endif()
