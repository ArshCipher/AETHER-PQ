# tools/standalone_sim/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

add_executable(uav_pqc_standalone_sim standalone_sim.cpp)
target_link_libraries(uav_pqc_standalone_sim PRIVATE uav_pqc::core)

add_executable(uav_pqc_validation_runner validation_runner.cpp)
target_link_libraries(uav_pqc_validation_runner PRIVATE uav_pqc::core)
