# cmake/cem-toolchain.cmake
# CMake Toolchain file for cross-compiling to ARMv7-A using Linaro gcc-linaro-7.5.0-2019.12-x86_64_arm-linux-gnueabi

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Specify the cross compilers
set(CMAKE_C_COMPILER arm-linux-gnueabi-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabi-g++)

# Target sysroot / toolchain environment path
list(APPEND CMAKE_FIND_ROOT_PATH 
    "/opt/gcc-linaro-7.5.0-2019.12-x86_64_arm-linux-gnueabi/arm-linux-gnueabi"
    "/opt/pqc/UAV/openssl-arm-install"
    "/opt/pqc/UAV/liboqs-arm-install"
)

# Control find_xxx search behavior:
# Search host for build utilities, but target sysroot for libraries/headers
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Compile flags optimization (Linaro armv7-a defaults to softfp/soft-float unless specified)
set(CMAKE_CXX_FLAGS "-march=armv7-a" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS "-march=armv7-a" CACHE STRING "" FORCE)
