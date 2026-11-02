# src/sim/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

uav_pqc_add_library(
    NAME    uav_pqc_sim
    SOURCES
        event_scheduler.cpp
        timer_manager.cpp
        timeline_logger.cpp
        simulation_context.cpp
    PUBLIC_LINKS
        uav_pqc_common
    PRIVATE_LINKS
        $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_sim EXPORT uav_pqc_targets)
endif()
