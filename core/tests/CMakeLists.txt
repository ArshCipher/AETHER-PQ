# tests/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

if(NOT UAV_PQC_BUILD_TESTS)
    return()
endif()

include(GoogleTest)

# ── Unit test executable ──────────────────────────────────────────────────────
add_executable(uav_pqc_tests
    unit/test_ml_kem.cpp
    unit/test_ml_dsa.cpp
    unit/test_x25519.cpp
    unit/test_ecdsa_p256.cpp
    unit/test_aes_gcm.cpp
    unit/test_chacha20_poly1305.cpp
    unit/test_hkdf.cpp
    unit/test_hybrid_kem.cpp
    unit/test_nonce_manager.cpp
    unit/test_session.cpp
    unit/test_session_cache.cpp
    unit/test_acpe.cpp
    unit/test_profile.cpp
    unit/test_fragment.cpp
    unit/test_retransmit.cpp
    unit/test_handshake.cpp
    unit/test_tree_kem.cpp
    unit/test_types.cpp
    unit/test_app_architecture.cpp
    unit/test_strong_types.cpp
    unit/test_app_pki.cpp
    unit/test_app_registration.cpp
    unit/test_app_auth.cpp
    unit/test_negotiation.cpp
    unit/test_secure_comm.cpp
    unit/test_transport.cpp
    unit/test_scheduler.cpp
    unit/test_diagnostics.cpp
    unit/test_clock.cpp
    unit/test_mavlink.cpp
    unit/test_app_battery.cpp
    unit/test_query_retrieve.cpp
    unit/test_d2d.cpp
)

target_link_libraries(uav_pqc_tests
    PRIVATE
        uav_pqc::core
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
)

target_include_directories(uav_pqc_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

gtest_discover_tests(uav_pqc_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    PROPERTIES TIMEOUT 120
)

# ── Benchmark executable ───────────────────────────────────────────────────────
if(UAV_PQC_BUILD_BENCHMARKS)
    add_executable(uav_pqc_benchmarks
        benchmarks/bench_kem.cpp
        benchmarks/bench_aead.cpp
        benchmarks/bench_hkdf.cpp
        benchmarks/bench_hybrid_kem.cpp
        benchmarks/bench_registration.cpp
        benchmarks/bench_auth.cpp
        benchmarks/bench_acpe.cpp
        benchmarks/bench_handshake.cpp
        benchmarks/bench_treekem.cpp
    )

    target_link_libraries(uav_pqc_benchmarks
        PRIVATE
            uav_pqc::core
            benchmark::benchmark
            benchmark::benchmark_main
    )
endif()
