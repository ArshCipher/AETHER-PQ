# src/policy/CMakeLists.txt

uav_pqc_add_library(
    NAME    uav_pqc_policy
    SOURCES
        profile.cpp
        acpe.cpp
    PUBLIC_LINKS
        uav_pqc_common
        uav_pqc_crypto
        uav_pqc_protocol
    PRIVATE_LINKS
        $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_policy EXPORT uav_pqc_targets)
endif()
