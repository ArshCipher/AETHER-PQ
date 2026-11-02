# Standard POSIX Linux HAL (also used as the base for Raspberry Pi)

uav_pqc_add_library(
    NAME    uav_pqc_platform_linux
    SOURCES
        hal_linux.cpp
        clock_linux.cpp
        random_linux.cpp
        aes_hw_linux.cpp
    PUBLIC_LINKS
        uav_pqc_common
)
