# src/platform/ns3/CMakeLists.txt

find_package(ns3 REQUIRED COMPONENTS core network internet)

uav_pqc_add_library(
    NAME    uav_pqc_platform_ns3
    SOURCES
        hal_ns3.cpp
        clock_ns3.cpp
        random_ns3.cpp
    PUBLIC_LINKS
        uav_pqc_common
        ns3::core
        ns3::network
        ns3::internet
)

target_compile_definitions(uav_pqc_platform_ns3 PUBLIC UAV_PQC_ENABLE_NS3)
