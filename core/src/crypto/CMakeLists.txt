# src/crypto/CMakeLists.txt
# ─────────────────────────────────────────────────────────────────────────────

uav_pqc_add_library(
    NAME    uav_pqc_crypto
    SOURCES
        ml_kem.cpp
        ml_dsa.cpp
        x25519.cpp
        ecdsa_p256.cpp
        aes_gcm.cpp
        chacha20_poly1305.cpp
        hkdf.cpp
        hybrid_kem.cpp
        default_provider.cpp
    PUBLIC_LINKS
        uav_pqc_common
        OQS::oqs
        OpenSSL::Crypto
        OpenSSL::SSL
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_crypto EXPORT uav_pqc_targets)
endif()
