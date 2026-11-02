# tools/hardware_benchmark/CMakeLists.txt
cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

add_executable(uav_pqc_hardware_benchmark hardware_benchmark.cpp)
target_link_libraries(uav_pqc_hardware_benchmark PRIVATE uav_pqc::core)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_hardware_benchmark RUNTIME DESTINATION bin)
endif()
