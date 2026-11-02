# src/CMakeLists.txt — Top-level source orchestrator
#
# Each subdirectory is a self-contained static library.  The root library
# target "uav_pqc_core" aggregates all sub-libraries for convenience.
# ─────────────────────────────────────────────────────────────────────────────

add_subdirectory(common)
add_subdirectory(crypto)
add_subdirectory(protocol)
add_subdirectory(policy)
add_subdirectory(group)
add_subdirectory(transport)
add_subdirectory(identity)
add_subdirectory(session)
add_subdirectory(platform)
add_subdirectory(app)
add_subdirectory(sim)
add_subdirectory(diagnostics)

# ── Aggregate library ─────────────────────────────────────────────────────────
# Consumers that want the full stack link against uav_pqc::core.
# Individual libraries remain available for granular linking.

add_library(uav_pqc_core INTERFACE)
add_library(uav_pqc::core ALIAS uav_pqc_core)

target_link_libraries(uav_pqc_core INTERFACE
    uav_pqc_common
    uav_pqc_crypto
    uav_pqc_protocol
    uav_pqc_policy
    uav_pqc_group
    uav_pqc_transport
    uav_pqc_identity
    uav_pqc_session
    uav_pqc_platform
    uav_pqc_app
    uav_pqc_sim
    uav_pqc_diagnostics
)

# ── Export for install ────────────────────────────────────────────────────────
if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_core EXPORT uav_pqc_targets)
endif()
