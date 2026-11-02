# cmake/armv7-toolchain.cmake
# CMake Toolchain file for cross-compiling to ARMv7-A (Cortex-A9, 32-bit Linux)
# Usage: cmake -DCMAKE_TOOLCHAIN_FILE=cmake/armv7-toolchain.cmake -B build-arm

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Specify the cross compilers
set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)

# Target sysroot / toolchain environment path
set(CMAKE_FIND_ROOT_PATH /usr/arm-linux-gnueabihf)

# Control find_xxx search behavior:
# Search host for build utilities, but target sysroot for libraries/headers
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Compile flags optimization for Cortex-A9 ARMv7-a hard float
set(CMAKE_CXX_FLAGS "-march=armv7-a -mfloat-abi=hard -mfpu=vfpv3-d16" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS "-march=armv7-a -mfloat-abi=hard -mfpu=vfpv3-d16" CACHE STRING "" FORCE)
