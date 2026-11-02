# CompilerOptions.cmake ─────────────────────────────────────────────────────────
#
# Sets warning flags, security hardening, sanitizers, and LTO for the project.
# Called once from the root CMakeLists.txt via uav_pqc_set_compiler_options().
#
# All flags are attached to an INTERFACE target "uav_pqc_compiler_options"
# and linked by each library target — avoiding pollution of transitive deps.
# ─────────────────────────────────────────────────────────────────────────────

function(uav_pqc_set_compiler_options)

    # Create the shared options target once
    if(TARGET uav_pqc_compiler_options)
        return()
    endif()
    add_library(uav_pqc_compiler_options INTERFACE)
    add_library(uav_pqc::compiler_options ALIAS uav_pqc_compiler_options)

    # ── GCC / Clang common flags ──────────────────────────────────────────────
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        target_compile_options(uav_pqc_compiler_options INTERFACE
            # Core warnings
            -Wall
            -Wextra
            -Wpedantic
            -Wshadow
            -Wnon-virtual-dtor
            -Woverloaded-virtual
            -Wcast-align
            -Wunused
            -Wconversion
            -Wsign-conversion
            -Wmisleading-indentation
            -Wnull-dereference
            -Wdouble-promotion
            -Wformat=2
            # C++20 specific
            -Wzero-as-null-pointer-constant
            # Errors for critical issues
            -Werror=return-type
            -Werror=uninitialized
        )

        # Security hardening flags for non-embedded targets
        if(NOT UAV_PQC_EMBEDDED)
            target_compile_options(uav_pqc_compiler_options INTERFACE
                -D_FORTIFY_SOURCE=2
                -fstack-protector-strong
            )
            if(NOT APPLE)
                target_link_options(uav_pqc_compiler_options INTERFACE
                    -Wl,-z,relro
                    -Wl,-z,now
                )
            endif()
        endif()

        # Release-mode optimizations
        target_compile_options(uav_pqc_compiler_options INTERFACE
            $<$<CONFIG:Release>:-O3 -DNDEBUG>
            $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG>
            $<$<CONFIG:MinSizeRel>:-Os -DNDEBUG>
            $<$<CONFIG:Debug>:-O0 -g3>
        )
    endif()

    # ── MSVC flags ────────────────────────────────────────────────────────────
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        target_compile_options(uav_pqc_compiler_options INTERFACE
            /W4
            /WX
            /permissive-
            /w14242 /w14254 /w14263 /w14265
            /w14287 /we4289 /w14296 /w14311
            /w14545 /w14546 /w14547 /w14549
            /w14555 /w14619 /w14640 /w14826
            /w14905 /w14906 /w14928
            /utf-8
        )
        target_compile_definitions(uav_pqc_compiler_options INTERFACE
            _CRT_SECURE_NO_WARNINGS
            WIN32_LEAN_AND_MEAN
            NOMINMAX
        )
    endif()

    # ── Clang-specific extras ─────────────────────────────────────────────────
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang")
        target_compile_options(uav_pqc_compiler_options INTERFACE
            -Wno-gnu-zero-variadic-macro-arguments
        )
    endif()

    # ── GNU-specific extras ───────────────────────────────────────────────────
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(uav_pqc_compiler_options INTERFACE
            -Wlogical-op
            -Wuseless-cast
        )
    endif()

    # ── Sanitizers (mutually exclusive in most practical setups) ──────────────
    if(UAV_PQC_ENABLE_ASAN AND UAV_PQC_ENABLE_TSAN)
        message(FATAL_ERROR "UAV_PQC_ENABLE_ASAN and UAV_PQC_ENABLE_TSAN cannot both be ON.")
    endif()

    if(UAV_PQC_ENABLE_ASAN)
        message(STATUS "[UAV-PQC] AddressSanitizer enabled")
        target_compile_options(uav_pqc_compiler_options INTERFACE
            -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls)
        target_link_options(uav_pqc_compiler_options INTERFACE
            -fsanitize=address)
    endif()

    if(UAV_PQC_ENABLE_TSAN)
        message(STATUS "[UAV-PQC] ThreadSanitizer enabled")
        target_compile_options(uav_pqc_compiler_options INTERFACE
            -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(uav_pqc_compiler_options INTERFACE
            -fsanitize=thread)
    endif()

    if(UAV_PQC_ENABLE_UBSAN)
        message(STATUS "[UAV-PQC] UndefinedBehaviorSanitizer enabled")
        target_compile_options(uav_pqc_compiler_options INTERFACE
            -fsanitize=undefined -fno-omit-frame-pointer)
        target_link_options(uav_pqc_compiler_options INTERFACE
            -fsanitize=undefined)
    endif()

    # ── Link-time optimisation (Release only, non-embedded) ───────────────────
    if(NOT UAV_PQC_EMBEDDED AND CMAKE_BUILD_TYPE STREQUAL "Release")
        include(CheckIPOSupported)
        check_ipo_supported(RESULT _ipo_ok OUTPUT _ipo_msg)
        if(_ipo_ok)
            message(STATUS "[UAV-PQC] LTO/IPO enabled for Release build")
            set_property(GLOBAL PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
        else()
            message(STATUS "[UAV-PQC] LTO/IPO not supported: ${_ipo_msg}")
        endif()
    endif()

    if(UAV_PQC_INSTALL)
        install(TARGETS uav_pqc_compiler_options EXPORT uav_pqc_targets)
    endif()

endfunction()
