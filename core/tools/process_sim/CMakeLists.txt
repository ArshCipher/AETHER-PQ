# tools/process_sim/CMakeLists.txt
cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

add_executable(uav_pqc_ca_node ca_node.cpp)
target_link_libraries(uav_pqc_ca_node PRIVATE uav_pqc::core)

add_executable(uav_pqc_gcs_node gcs_node.cpp)
target_link_libraries(uav_pqc_gcs_node PRIVATE uav_pqc::core)

add_executable(uav_pqc_uav_node uav_node.cpp jo_jpeg.cpp)
target_link_libraries(uav_pqc_uav_node PRIVATE uav_pqc::core)

add_executable(uav_pqc_cem_node cem_node.cpp)
target_link_libraries(uav_pqc_cem_node PRIVATE uav_pqc::core)

