# src/group/CMakeLists.txt

uav_pqc_add_library(
    NAME    uav_pqc_group
    SOURCES
        tree_kem.cpp
        membership.cpp
        group_key.cpp
    PUBLIC_LINKS
        uav_pqc_common
        uav_pqc_crypto
        uav_pqc_protocol
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_group EXPORT uav_pqc_targets)
endif()
