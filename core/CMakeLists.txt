cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

# ── Project declaration ────────────────────────────────────────────────────────
project(uav_pqc
    VERSION      0.1.0
    DESCRIPTION  "Post-Quantum Communication Architecture for Heterogeneous UAV Networks"
    HOMEPAGE_URL "https://github.com/uav-pqc/uav-pqc"
    LANGUAGES    CXX C
)

# ── C++20 standard — mandatory, no compiler extensions ────────────────────────
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)
set(CMAKE_C_STANDARD            11)
set(CMAKE_C_STANDARD_REQUIRED   ON)
set(CMAKE_C_EXTENSIONS          OFF)


# ── Build type default ────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# ── Export compile commands for clangd / static analysis ──────────────────────
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── CMake module path ─────────────────────────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ═════════════════════════════════════════════════════════════════════════════
# Build options
# ═════════════════════════════════════════════════════════════════════════════
option(UAV_PQC_BUILD_TESTS       "Build unit and integration tests"     ON)
option(UAV_PQC_BUILD_BENCHMARKS  "Build Google Benchmark suite"         OFF)
option(UAV_PQC_BUILD_TOOLS       "Build developer utility binaries"     ON)
option(UAV_PQC_BUILD_DOCS        "Build Doxygen documentation"          OFF)
option(UAV_PQC_ENABLE_NS3        "Enable ns-3 simulation platform shim" OFF)
option(UAV_PQC_ENABLE_ASAN       "Enable AddressSanitizer"              OFF)
option(UAV_PQC_ENABLE_TSAN       "Enable ThreadSanitizer"               OFF)
option(UAV_PQC_ENABLE_UBSAN      "Enable UndefinedBehaviorSanitizer"    OFF)
option(UAV_PQC_INSTALL           "Generate install targets"             ON)

# Embedded target: disables STL exceptions and RTTI in platform code
option(UAV_PQC_EMBEDDED          "Compile for embedded Linux / STM32"   OFF)

# ═════════════════════════════════════════════════════════════════════════════
# Helpers, compiler flags, dependencies
# ═════════════════════════════════════════════════════════════════════════════
include(UavPqcHelpers)
uav_pqc_detect_platform()

include(CompilerOptions)
uav_pqc_set_compiler_options()

include(Dependencies)
uav_pqc_find_system_dependencies()
uav_pqc_fetch_lightweight_dependencies()

find_package(OpenCV QUIET)
if(OpenCV_FOUND)
    message(STATUS "[UAV-PQC] Found OpenCV ${OpenCV_VERSION} at ${OpenCV_DIR}")
    add_compile_definitions(AETHER_PQC_HAS_OPENCV)
else()
    message(STATUS "[UAV-PQC] OpenCV not found, building with fallback baseline JPEG writer.")
endif()


# ═════════════════════════════════════════════════════════════════════════════
# Library source
# ═════════════════════════════════════════════════════════════════════════════
add_subdirectory(src)

if(OpenCV_FOUND)
    target_link_libraries(uav_pqc_core INTERFACE ${OpenCV_LIBS})
    target_include_directories(uav_pqc_core INTERFACE ${OpenCV_INCLUDE_DIRS})
endif()

# ═════════════════════════════════════════════════════════════════════════════
# Optional sub-targets
# ═════════════════════════════════════════════════════════════════════════════
if(UAV_PQC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Benchmarks are built within the tests subdirectory if enabled.

if(UAV_PQC_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(UAV_PQC_BUILD_DOCS)
    add_subdirectory(docs)
endif()

# ═════════════════════════════════════════════════════════════════════════════
# Install
# ═════════════════════════════════════════════════════════════════════════════
if(UAV_PQC_INSTALL)
    include(InstallRules)
    uav_pqc_configure_install()
endif()

# ═════════════════════════════════════════════════════════════════════════════
# Configuration summary
# ═════════════════════════════════════════════════════════════════════════════
message(STATUS "")
message(STATUS "╔══════════════════════════════════════════════╗")
message(STATUS "║          UAV-PQC Build Configuration         ║")
message(STATUS "╠══════════════════════════════════════════════╣")
message(STATUS "║  Version         : ${PROJECT_VERSION}")
message(STATUS "║  Build type      : ${CMAKE_BUILD_TYPE}")
message(STATUS "║  C++ standard    : C++${CMAKE_CXX_STANDARD}")
message(STATUS "║  Platform        : ${UAV_PQC_PLATFORM}")
message(STATUS "║  Compiler        : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "║  liboqs          : ${OQS_VERSION}")
message(STATUS "║  OpenSSL         : ${OPENSSL_VERSION}")
message(STATUS "╠══════════════════════════════════════════════╣")
message(STATUS "║  Tests           : ${UAV_PQC_BUILD_TESTS}")
message(STATUS "║  Benchmarks      : ${UAV_PQC_BUILD_BENCHMARKS}")
message(STATUS "║  Tools           : ${UAV_PQC_BUILD_TOOLS}")
message(STATUS "║  ns-3 shim       : ${UAV_PQC_ENABLE_NS3}")
message(STATUS "║  Embedded mode   : ${UAV_PQC_EMBEDDED}")
message(STATUS "║  ASan            : ${UAV_PQC_ENABLE_ASAN}")
message(STATUS "║  TSan            : ${UAV_PQC_ENABLE_TSAN}")
message(STATUS "║  UBSan           : ${UAV_PQC_ENABLE_UBSAN}")
message(STATUS "║  Install prefix  : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "╚══════════════════════════════════════════════╝")
message(STATUS "")
