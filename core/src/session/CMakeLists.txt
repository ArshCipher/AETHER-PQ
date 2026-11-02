# src/session/CMakeLists.txt

uav_pqc_add_library(
    NAME    uav_pqc_session
    SOURCES
        nonce_manager.cpp
        session.cpp
        session_cache.cpp
        secure_comm.cpp
        d2d_manager.cpp
    PUBLIC_LINKS
        uav_pqc_common
        uav_pqc_crypto
        uav_pqc_protocol
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_session EXPORT uav_pqc_targets)
endif()
