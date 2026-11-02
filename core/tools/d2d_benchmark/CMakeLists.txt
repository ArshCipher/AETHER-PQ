# tools/d2d_benchmark/CMakeLists.txt

add_executable(uav_pqc_d2d_benchmark d2d_benchmark_runner.cpp)
target_link_libraries(uav_pqc_d2d_benchmark PRIVATE uav_pqc::core)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_d2d_benchmark RUNTIME DESTINATION bin)
endif()
