# tools/swarm_sim/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

add_executable(uav_pqc_swarm_sim
    swarm_sim.cpp
)

target_link_libraries(uav_pqc_swarm_sim
    PRIVATE
        uav_pqc::core
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_swarm_sim RUNTIME DESTINATION bin)
endif()
