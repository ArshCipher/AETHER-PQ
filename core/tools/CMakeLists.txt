# tools/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

add_executable(uav_pqc_keygen keygen/keygen.cpp)
target_link_libraries(uav_pqc_keygen PRIVATE uav_pqc::core)

add_executable(uav_pqc_certgen certgen/certgen.cpp)
target_link_libraries(uav_pqc_certgen PRIVATE uav_pqc::core)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_keygen uav_pqc_certgen RUNTIME DESTINATION bin)
endif()

if(UAV_PQC_ENABLE_NS3)
    add_subdirectory(ns3_sim)
endif()

add_subdirectory(standalone_sim)
add_subdirectory(process_sim)
add_subdirectory(swarm_sim)
add_subdirectory(hardware_benchmark)
add_subdirectory(d2d_benchmark)

