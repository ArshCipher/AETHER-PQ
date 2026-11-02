# src/diagnostics/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

uav_pqc_add_library(
    NAME    uav_pqc_diagnostics
    SOURCES
        metrics.cpp
    PUBLIC_LINKS
        uav_pqc_common
        uav_pqc_platform
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_diagnostics EXPORT uav_pqc_targets)
endif()
