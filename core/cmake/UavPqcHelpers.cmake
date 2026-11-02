# UavPqcHelpers.cmake ──────────────────────────────────────────────────────────
#
# General-purpose CMake utilities used throughout the project.
#
# Functions provided:
#   uav_pqc_detect_platform()         — Sets UAV_PQC_PLATFORM cache variable
#   uav_pqc_add_library(name ...)     — Wrapper: creates lib + installs headers
#   uav_pqc_add_test(name ...)        — Wrapper: creates GTest binary + CTest entry
#   uav_pqc_add_benchmark(name ...)   — Wrapper: creates benchmark binary
# ─────────────────────────────────────────────────────────────────────────────

# ── Platform detection ─────────────────────────────────────────────────────────
function(uav_pqc_detect_platform)
    if(DEFINED UAV_PQC_PLATFORM)
        return()
    endif()

    # Cross-compile toolchain may preset the platform
    if(DEFINED UAV_PQC_PLATFORM_OVERRIDE)
        set(UAV_PQC_PLATFORM "${UAV_PQC_PLATFORM_OVERRIDE}" CACHE STRING "Target platform" FORCE)
        return()
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Detect Raspberry Pi by /proc/cpuinfo model string
        if(EXISTS "/proc/cpuinfo")
            file(READ "/proc/cpuinfo" _cpuinfo)
            if(_cpuinfo MATCHES "Raspberry Pi")
                set(_platform "RaspberryPi")
            else()
                set(_platform "Linux")
            endif()
            unset(_cpuinfo)
        else()
            set(_platform "Linux")
        endif()

        # ns-3 shim overrides the platform label (still Linux underneath)
        if(UAV_PQC_ENABLE_NS3)
            set(_platform "ns3")
        endif()
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(_platform "macOS")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(_platform "Windows")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Generic")
        # Bare-metal cross-compile (STM32, etc.)
        set(_platform "Embedded")
    else()
        set(_platform "Unknown")
    endif()

    set(UAV_PQC_PLATFORM "${_platform}" CACHE STRING "Detected target platform" FORCE)
    unset(_platform)
endfunction()

# ── Create a module library ────────────────────────────────────────────────────
#
# Usage:
#   uav_pqc_add_library(
#       NAME        <target-name>          # e.g. uav_pqc_crypto
#       SOURCES     <src1.cpp> ...
#       PUBLIC_HEADERS <hdr1.hpp> ...      # relative to include/
#       PUBLIC_LINKS   <dep1> ...          # propagated link deps
#       PRIVATE_LINKS  <dep2> ...          # non-propagated link deps
#   )
#
function(uav_pqc_add_library)
    cmake_parse_arguments(ARG
        ""
        "NAME"
        "SOURCES;PUBLIC_LINKS;PRIVATE_LINKS"
        ${ARGN}
    )

    if(NOT ARG_NAME)
        message(FATAL_ERROR "uav_pqc_add_library: NAME is required")
    endif()

    add_library(${ARG_NAME} STATIC ${ARG_SOURCES})
    add_library(uav_pqc::${ARG_NAME} ALIAS ${ARG_NAME})

    target_include_directories(${ARG_NAME}
        PUBLIC
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    )

    target_link_libraries(${ARG_NAME}
        PUBLIC  ${ARG_PUBLIC_LINKS}  uav_pqc::compiler_options
        PRIVATE ${ARG_PRIVATE_LINKS}
    )

    set_target_properties(${ARG_NAME} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        CXX_VISIBILITY_PRESET     default
        VISIBILITY_INLINES_HIDDEN OFF
    )
endfunction()

# ── Create a GoogleTest binary with CTest registration ─────────────────────────
#
# Usage:
#   uav_pqc_add_test(
#       NAME    <test-name>
#       SOURCES <test1.cpp> ...
#       LINKS   <lib1> ...
#   )
#
function(uav_pqc_add_test)
    cmake_parse_arguments(ARG "" "NAME" "SOURCES;LINKS" ${ARGN})

    if(NOT ARG_NAME)
        message(FATAL_ERROR "uav_pqc_add_test: NAME is required")
    endif()

    add_executable(${ARG_NAME} ${ARG_SOURCES})

    target_link_libraries(${ARG_NAME}
        PRIVATE
            ${ARG_LINKS}
            GTest::gtest_main
            GTest::gmock
            uav_pqc::compiler_options
    )

    target_include_directories(${ARG_NAME}
        PRIVATE
            "${PROJECT_SOURCE_DIR}/include"
            "${PROJECT_SOURCE_DIR}/tests"
    )

    include(GoogleTest)
    gtest_discover_tests(${ARG_NAME}
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        PROPERTIES        TIMEOUT 60
    )
endfunction()

# ── Create a Google Benchmark binary ──────────────────────────────────────────
#
# Usage:
#   uav_pqc_add_benchmark(
#       NAME    <bench-name>
#       SOURCES <bench1.cpp> ...
#       LINKS   <lib1> ...
#   )
#
function(uav_pqc_add_benchmark)
    cmake_parse_arguments(ARG "" "NAME" "SOURCES;LINKS" ${ARGN})

    if(NOT ARG_NAME)
        message(FATAL_ERROR "uav_pqc_add_benchmark: NAME is required")
    endif()

    add_executable(${ARG_NAME} ${ARG_SOURCES})

    target_link_libraries(${ARG_NAME}
        PRIVATE
            ${ARG_LINKS}
            benchmark::benchmark_main
            uav_pqc::compiler_options
    )

    target_include_directories(${ARG_NAME}
        PRIVATE "${PROJECT_SOURCE_DIR}/include"
    )
endfunction()
