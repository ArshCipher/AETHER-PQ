# src/transport/CMakeLists.txt

uav_pqc_add_library(
    NAME    uav_pqc_transport
    SOURCES
        fragment.cpp
        retransmit.cpp
        transport.cpp
        channel_emulator.cpp
    PUBLIC_LINKS
        uav_pqc_common
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_transport EXPORT uav_pqc_targets)
endif()
