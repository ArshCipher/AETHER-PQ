# InstallRules.cmake ────────────────────────────────────────────────────────────
#
# Defines install targets, packaging rules, and the CMake package config files
# so that downstream projects can consume uav_pqc via find_package(uav_pqc).
#
# Entry point: uav_pqc_configure_install()
# ─────────────────────────────────────────────────────────────────────────────

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

function(uav_pqc_configure_install)

    # ── Install public headers ─────────────────────────────────────────────────
    install(
        DIRECTORY "${PROJECT_SOURCE_DIR}/include/uav_pqc"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING PATTERN "*.hpp"
    )

    # ── Install runtime config files ───────────────────────────────────────────
    install(
        DIRECTORY "${PROJECT_SOURCE_DIR}/config/"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/uav_pqc/config"
    )

    # ── CMake package config ───────────────────────────────────────────────────
    set(_cmake_install_dir "${CMAKE_INSTALL_LIBDIR}/cmake/uav_pqc")

    # Generate version file
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/uav_pqc-config-version.cmake"
        VERSION       "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )

    # Generate config file from template
    configure_package_config_file(
        "${PROJECT_SOURCE_DIR}/cmake/uav_pqc-config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/uav_pqc-config.cmake"
        INSTALL_DESTINATION "${_cmake_install_dir}"
    )

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/uav_pqc-config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/uav_pqc-config-version.cmake"
            "${PROJECT_SOURCE_DIR}/cmake/FindLibOQS.cmake"
        DESTINATION "${_cmake_install_dir}"
    )

    # Install the export set (all targets tagged EXPORT uav_pqc_targets)
    install(
        EXPORT      uav_pqc_targets
        FILE        uav_pqc-targets.cmake
        NAMESPACE   uav_pqc::
        DESTINATION "${_cmake_install_dir}"
    )

    # ── pkg-config .pc file ────────────────────────────────────────────────────
    set(UAV_PQC_PC_PREFIX   "${CMAKE_INSTALL_PREFIX}")
    set(UAV_PQC_PC_INCDIR   "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
    set(UAV_PQC_PC_LIBDIR   "${CMAKE_INSTALL_FULL_LIBDIR}")
    set(UAV_PQC_PC_VERSION  "${PROJECT_VERSION}")
    configure_file(
        "${PROJECT_SOURCE_DIR}/cmake/uav_pqc.pc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/uav_pqc.pc"
        @ONLY
    )
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/uav_pqc.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
    )

endfunction()
