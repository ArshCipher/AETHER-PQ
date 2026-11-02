# src/common/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

uav_pqc_add_library(
    NAME    uav_pqc_common
    SOURCES
        types.cpp
        error.cpp
        logging.cpp
        strong_types.cpp
    PUBLIC_LINKS
        $<$<NOT:$<BOOL:${UAV_PQC_EMBEDDED}>>:spdlog::spdlog_header_only>
        $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>
)

if(UAV_PQC_EMBEDDED)
    target_compile_definitions(uav_pqc_common PUBLIC UAV_PQC_EMBEDDED)
endif()

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_common EXPORT uav_pqc_targets)
endif()
