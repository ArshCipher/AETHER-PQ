# Dependencies.cmake ────────────────────────────────────────────────────────────
#
# Hybrid dependency management:
#   • System-installed (find_package):  liboqs, OpenSSL, ns-3
#   • FetchContent (pinned, lightweight): spdlog, fmt, nlohmann/json,
#                                         GoogleTest, Google Benchmark
#
# Entry points:
#   uav_pqc_find_system_dependencies()      — called for system libs
#   uav_pqc_fetch_lightweight_dependencies() — called for FetchContent libs
# ─────────────────────────────────────────────────────────────────────────────

include(FetchContent)

# ── Version pins — override via -DUAV_PQC_<X>_VERSION=<ver> ───────────────────
set(UAV_PQC_SPDLOG_VERSION       "1.14.1" CACHE STRING "spdlog version to fetch")
set(UAV_PQC_FMT_VERSION          "11.0.2" CACHE STRING "fmtlib version to fetch")
set(UAV_PQC_NLOHMANN_JSON_VERSION "3.11.3" CACHE STRING "nlohmann/json version to fetch")
set(UAV_PQC_GOOGLETEST_VERSION   "1.14.0" CACHE STRING "GoogleTest version to fetch")
set(UAV_PQC_BENCHMARK_VERSION    "1.8.4"  CACHE STRING "Google Benchmark version to fetch")

# Speed: avoid rechecking remote state after the first download
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

# ═══════════════════════════════════════════════════════════════════════════════
# System-installed dependencies
# ═══════════════════════════════════════════════════════════════════════════════
function(uav_pqc_find_system_dependencies)

    # ── OpenSSL 3.x (EVP AES-GCM, ChaCha20-Poly1305, X25519, ECDSA-P256, HKDF)
    find_package(OpenSSL 3.0 QUIET)
    if(NOT OpenSSL_FOUND)
        message(FATAL_ERROR
            "\n"
            "  [UAV-PQC] FATAL: OpenSSL 3.0 or newer was not found on this system.\n"
            "\n"
            "  Installation instructions:\n"
            "    Ubuntu / Debian / Raspberry Pi OS:\n"
            "      sudo apt-get update && sudo apt-get install -y libssl-dev\n"
            "\n"
            "    Fedora / RHEL / CentOS Stream:\n"
            "      sudo dnf install openssl-devel\n"
            "\n"
            "    Arch Linux / Manjaro:\n"
            "      sudo pacman -S openssl\n"
            "\n"
            "    Build from source (any distro):\n"
            "      https://github.com/openssl/openssl/blob/master/INSTALL.md\n"
            "\n"
            "  If OpenSSL 3 is installed in a non-standard prefix, set:\n"
            "    -DOPENSSL_ROOT_DIR=<prefix>\n"
            "\n"
        )
    endif()
    message(STATUS "[UAV-PQC] Found OpenSSL ${OPENSSL_VERSION} at ${OPENSSL_INCLUDE_DIR}")

    # ── liboqs (ML-KEM, ML-DSA) ───────────────────────────────────────────────
    find_package(LibOQS QUIET)
    if(NOT LibOQS_FOUND)
        message(FATAL_ERROR
            "\n"
            "  [UAV-PQC] FATAL: liboqs was not found on this system.\n"
            "\n"
            "  liboqs provides ML-KEM (FIPS 203) and ML-DSA (FIPS 204) — required.\n"
            "\n"
            "  Build and install from source:\n"
            "    # Dependencies first\n"
            "    sudo apt-get install -y cmake ninja-build libssl-dev\n"
            "\n"
            "    # Clone (shallow) and build\n"
            "    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git\n"
            "    cmake -S liboqs -B liboqs/build \\\\\n"
            "          -DOQS_USE_OPENSSL=ON \\\\\n"
            "          -DBUILD_SHARED_LIBS=OFF \\\\\n"
            "          -DCMAKE_BUILD_TYPE=Release\n"
            "    cmake --build liboqs/build --parallel\n"
            "    sudo cmake --install liboqs/build   # installs to /usr/local by default\n"
            "\n"
            "  If installed to a custom prefix, guide CMake with:\n"
            "    -DOQS_ROOT_DIR=<prefix>\n"
            "\n"
        )
    endif()
    message(STATUS "[UAV-PQC] Found liboqs ${OQS_VERSION} at ${OQS_INCLUDE_DIRS}")

    # ── ns-3 (optional — only when UAV_PQC_ENABLE_NS3=ON) ────────────────────
    if(UAV_PQC_ENABLE_NS3)
        find_package(MPI QUIET)
        find_package(ns3 QUIET COMPONENTS core network internet)
        if(NOT ns3_FOUND)
            message(FATAL_ERROR
                "\n"
                "  [UAV-PQC] FATAL: ns-3 not found but UAV_PQC_ENABLE_NS3=ON.\n"
                "\n"
                "  Build ns-3 from source:\n"
                "    git clone https://gitlab.com/nsnam/ns-3-dev.git\n"
                "    cd ns-3-dev\n"
                "    ./ns3 configure --enable-examples --enable-tests\n"
                "    ./ns3 build\n"
                "    sudo ./ns3 install\n"
                "\n"
                "  Then pass:\n"
                "    -Dns3_DIR=<ns3-install-prefix>/lib/cmake/ns3\n"
                "\n"
            )
        endif()
        message(STATUS "[UAV-PQC] Found ns-3 ${ns3_VERSION}")
    endif()

endfunction()

# ═══════════════════════════════════════════════════════════════════════════════
# FetchContent-managed lightweight dependencies
# ═══════════════════════════════════════════════════════════════════════════════
function(uav_pqc_fetch_lightweight_dependencies)

    if(APPLE)
        set(SPDLOG_USE_STD_FORMAT       ON  CACHE BOOL "" FORCE)
    else()
        set(SPDLOG_USE_STD_FORMAT       OFF  CACHE BOOL "" FORCE)
    endif()
    set(SPDLOG_FMT_EXTERNAL         OFF CACHE BOOL "" FORCE)
    set(SPDLOG_FMT_EXTERNAL_HO      OFF CACHE BOOL "" FORCE)
    set(SPDLOG_BUILD_STATIC         OFF CACHE BOOL "" FORCE)
    set(SPDLOG_BUILD_SHARED         OFF CACHE BOOL "" FORCE)
    set(SPDLOG_BUILD_EXAMPLE        OFF CACHE BOOL "" FORCE)
    set(SPDLOG_BUILD_TESTS          OFF CACHE BOOL "" FORCE)
    set(SPDLOG_INSTALL              OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG        "v${UAV_PQC_SPDLOG_VERSION}"
        GIT_SHALLOW    ON
        GIT_PROGRESS   ON
    )

    # ── nlohmann/json — header-only; disable its own tests ───────────────────
    set(JSON_BuildTests   OFF CACHE BOOL "" FORCE)
    set(JSON_Install      OFF CACHE BOOL "" FORCE)
    set(JSON_MultipleHeaders OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        "v${UAV_PQC_NLOHMANN_JSON_VERSION}"
        GIT_SHALLOW    ON
        GIT_PROGRESS   ON
    )

    # ── GoogleTest ────────────────────────────────────────────────────────────
    if(UAV_PQC_BUILD_TESTS)
        set(INSTALL_GTEST          OFF CACHE BOOL "" FORCE)
        set(gtest_force_shared_crt ON  CACHE BOOL "" FORCE)
        FetchContent_Declare(googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG        "v${UAV_PQC_GOOGLETEST_VERSION}"
            GIT_SHALLOW    ON
            GIT_PROGRESS   ON
        )
    endif()

    # ── Google Benchmark ──────────────────────────────────────────────────────
    if(UAV_PQC_BUILD_BENCHMARKS)
        set(BENCHMARK_ENABLE_TESTING        OFF CACHE BOOL "" FORCE)
        set(BENCHMARK_ENABLE_INSTALL        OFF CACHE BOOL "" FORCE)
        set(BENCHMARK_ENABLE_GTEST_TESTS    OFF CACHE BOOL "" FORCE)
        set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON  CACHE BOOL "" FORCE)
        FetchContent_Declare(benchmark
            GIT_REPOSITORY https://github.com/google/benchmark.git
            GIT_TAG        "v${UAV_PQC_BENCHMARK_VERSION}"
            GIT_SHALLOW    ON
            GIT_PROGRESS   ON
        )
    endif()

    # ── Populate all declared content ──────────────────────────────────────────
    FetchContent_MakeAvailable(spdlog nlohmann_json)

    if(TARGET spdlog)
        set_property(TARGET spdlog PROPERTY EXCLUDE_FROM_ALL TRUE)
    endif()

    if(UAV_PQC_BUILD_TESTS)
        FetchContent_MakeAvailable(googletest)
    endif()

    if(UAV_PQC_BUILD_BENCHMARKS)
        FetchContent_MakeAvailable(benchmark)
    endif()



endfunction()
