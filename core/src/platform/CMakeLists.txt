# src/platform/CMakeLists.txt
#
# Platform selection: exactly one platform implementation is compiled based on
# the detected UAV_PQC_PLATFORM and build options.  The platform library
# always exposes the same make_platform_hal() factory function.
# ─────────────────────────────────────────────────────────────────────────────

if(UAV_PQC_ENABLE_NS3)
    add_subdirectory(ns3)
    set(_uav_pqc_platform_lib uav_pqc_platform_ns3)
elseif(UAV_PQC_PLATFORM STREQUAL "Embedded")
    add_subdirectory(stm32)
    set(_uav_pqc_platform_lib uav_pqc_platform_stm32)
else()
    # Default: standard POSIX Linux (covers standard Linux, macOS, Raspberry Pi, Orange Pi, Jetson, BeagleBone, generic ARM Linux)
    add_subdirectory(linux)
    set(_uav_pqc_platform_lib uav_pqc_platform_linux)
endif()

# Re-export as the generic alias consumed by all other modules
add_library(uav_pqc_platform ALIAS ${_uav_pqc_platform_lib})

if(UAV_PQC_INSTALL)
    install(TARGETS ${_uav_pqc_platform_lib} EXPORT uav_pqc_targets)
endif()
