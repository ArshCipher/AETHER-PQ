# FindLibOQS.cmake ─────────────────────────────────────────────────────────────
#
# Locate the Open Quantum Safe liboqs library (https://github.com/open-quantum-safe/liboqs).
#
# Provides the imported target:
#   OQS::oqs   — liboqs shared/static library with include paths attached
#
# Output cache variables (set when found):
#   OQS_FOUND          TRUE if both the header and library were located
#   OQS_INCLUDE_DIRS   Path to the directory containing oqs/oqs.h
#   OQS_LIBRARIES      Full path to the liboqs library
#   OQS_VERSION        Version string extracted from oqs/oqs.h
#
# Search hints (can be overridden by the caller):
#   OQS_ROOT_DIR       Set to the liboqs install prefix to guide all searches
#
# ─────────────────────────────────────────────────────────────────────────────

cmake_minimum_required(VERSION 3.14)

# Use pkg-config as a secondary hint source when available
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_OQS QUIET liboqs)
endif()

# ── Header search ─────────────────────────────────────────────────────────────
find_path(OQS_INCLUDE_DIR
    NAMES oqs/oqs.h
    HINTS
        ${OQS_ROOT_DIR}/include
        ${PC_OQS_INCLUDE_DIRS}
    PATHS
        /usr/include
        /usr/local/include
        /opt/liboqs/include
        /opt/local/include
    DOC "Directory containing oqs/oqs.h"
)

# ── Library search ────────────────────────────────────────────────────────────
find_library(OQS_LIBRARY
    NAMES oqs liboqs
    HINTS
        ${OQS_ROOT_DIR}/lib
        ${OQS_ROOT_DIR}/lib64
        ${PC_OQS_LIBRARY_DIRS}
    PATHS
        /usr/lib
        /usr/local/lib
        /usr/lib/x86_64-linux-gnu
        /usr/lib/aarch64-linux-gnu
        /usr/lib/arm-linux-gnueabihf
        /opt/liboqs/lib
        /opt/local/lib
    DOC "Full path to liboqs (.so or .a)"
)

# ── Version extraction ────────────────────────────────────────────────────────
if(OQS_INCLUDE_DIR AND EXISTS "${OQS_INCLUDE_DIR}/oqs/oqs.h")
    # The header exposes: #define OQS_VERSION_TEXT "x.y.z"
    file(STRINGS "${OQS_INCLUDE_DIR}/oqs/oqs.h" _oqs_ver_line
         REGEX "#define[ \t]+OQS_VERSION_TEXT[ \t]+")
    if(_oqs_ver_line)
        string(REGEX REPLACE
            ".*#define[ \t]+OQS_VERSION_TEXT[ \t]+\"([^\"]+)\".*"
            "\\1"
            OQS_VERSION
            "${_oqs_ver_line}"
        )
    else()
        set(OQS_VERSION "unknown")
    endif()
    unset(_oqs_ver_line)
endif()

# ── Standard result handling ──────────────────────────────────────────────────
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibOQS
    REQUIRED_VARS OQS_LIBRARY OQS_INCLUDE_DIR
    VERSION_VAR   OQS_VERSION
    FAIL_MESSAGE  "liboqs not found. See cmake/FindLibOQS.cmake for installation instructions."
)

# ── Populate output variables and imported target ─────────────────────────────
if(LibOQS_FOUND)
    set(OQS_LIBRARIES    "${OQS_LIBRARY}"      CACHE STRING "liboqs link library")
    set(OQS_INCLUDE_DIRS "${OQS_INCLUDE_DIR}"  CACHE PATH   "liboqs include directory")

    if(NOT TARGET OQS::oqs)
        # Detect whether the found artifact is shared or static
        get_filename_component(_oqs_ext "${OQS_LIBRARY}" EXT)
        if(_oqs_ext STREQUAL ".a" OR _oqs_ext STREQUAL ".lib")
            set(_oqs_type STATIC)
        else()
            set(_oqs_type SHARED)
        endif()

        add_library(OQS::oqs ${_oqs_type} IMPORTED)
        set_target_properties(OQS::oqs PROPERTIES
            IMPORTED_LOCATION             "${OQS_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OQS_INCLUDE_DIR}"
        )

        # Forward any pkg-config compile options
        if(PC_OQS_CFLAGS_OTHER)
            set_property(TARGET OQS::oqs APPEND PROPERTY
                INTERFACE_COMPILE_OPTIONS ${PC_OQS_CFLAGS_OTHER})
        endif()

        unset(_oqs_ext)
        unset(_oqs_type)
    endif()
endif()

mark_as_advanced(OQS_INCLUDE_DIR OQS_LIBRARY OQS_VERSION)
