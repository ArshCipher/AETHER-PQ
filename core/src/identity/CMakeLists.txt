# src/identity/CMakeLists.txt

uav_pqc_add_library(
    NAME    uav_pqc_identity
    SOURCES
        certificate.cpp
        trust_chain.cpp
        credential_store.cpp
    PUBLIC_LINKS
        uav_pqc_common
        uav_pqc_crypto
        OpenSSL::Crypto
)

if(UAV_PQC_INSTALL)
    install(TARGETS uav_pqc_identity EXPORT uav_pqc_targets)
endif()
