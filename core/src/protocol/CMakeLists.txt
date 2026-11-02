# src/protocol/CMakeLists.txt

uav_pqc_add_library(
    NAME    uav_pqc_protocol
    SOURCES
        suite.cpp
        message.cpp
        handshake.cpp
        registration.cpp
        auth.cpp
        negotiation.cpp
        session_establishment.cpp
        d2d_messages.cpp
        d2d_handshake.cpp
    PUBLIC_LINKS
        uav_pqc_common
        uav_pqc_crypto
        uav_pqc_session
        uav_pqc_identity
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_protocol EXPORT uav_pqc_targets)
endif()
