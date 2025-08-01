cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_VERSION 0.2.0)
project (libiop
  DESCRIPTION "Library for building IOP based SNARKs"
  LANGUAGES CXX C)

# --- Platform-Specific Dependency Handling ---
if(EMSCRIPTEN)
    message(STATUS "Emscripten build: Defining placeholder variables for GMP & Libsodium.")
    set(GMP_FOUND TRUE)
    set(SODIUM_FOUND TRUE)
    set(GMP_LIBRARIES "")
    set(SODIUM_LIBRARIES "")
else()
    # For native builds, use PkgConfig to find libraries.
    # This is more robust and works well with both vcpkg on Windows and apt/brew on Linux/macOS.
    message(STATUS "Native build: Searching for system libraries using PkgConfig.")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GMP REQUIRED gmp)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    include_directories(${GMP_INCLUDE_DIRS})
    include_directories(${SODIUM_INCLUDE_DIRS})
    # Add the library directories to the linker search path
    link_directories(${GMP_LIBRARY_DIRS})
    link_directories(${SODIUM_LIBRARY_DIRS})
endif()

# --- Windows-Specific Fixes ---
if(WIN32)
    # The default BN128 curve uses 'ate-pairing', which is incompatible with MSVC.
    # Force the portable ALT_BN128 curve on Windows.
    set(CURVE "ALT_BN128" CACHE STRING "Set curve to ALT_BN128 for Windows compatibility" FORCE)
    # The USE_ASM option enables GCC/Clang-specific intrinsics that fail on MSVC.
    set(USE_ASM OFF CACHE BOOL "Disable assembly on Windows for compatibility" FORCE)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- Build Options ---
option(PERFORMANCE "Enable link-time and aggressive optimizations" OFF)
option(MULTICORE "Enable parallelized execution, using OpenMP" OFF)
option(USE_ASM "Use architecture-specific optimized assembly code" ON)
set(OPT_FLAGS "" CACHE STRING "Override C++ compiler optimization flags")

# --- Compiler Flag Configuration ---
if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(DISABLED_WARNINGS "-Wno-sign-compare -Wno-shadow -Wno-unused-variable -Wno-unused-parameter")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra -Wfatal-errors ${DISABLED_WARNINGS}")
endif()

# Add native-specific optimization flags ONLY for non-MSVC compilers.
if(NOT MSVC)
  if("${OPT_FLAGS}" STREQUAL "")
    set(OPT_FLAGS "-ggdb3 -O3 -march=native -mtune=native")
  endif()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}")

  if("${USE_ASM}")
    add_definitions(-DUSE_ASM)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mpclmul -msse4.1")
  endif()
endif()

# --- Add Subdirectories ---
add_subdirectory(depends)
add_subdirectory(libiop)

# ===================================================================
# Final FFI Target Configuration
# ===================================================================

if(EMSCRIPTEN)
    # WebAssembly build configuration (not used for this guide)
    # ...
else()
    # --- NATIVE SHARED LIBRARY BUILD ---
    message(STATUS "Configuring Native Shared Library FFI target (libiop_ffi)")

    add_library(libiop_ffi SHARED
        ${CMAKE_CURRENT_SOURCE_DIR}/ffi/libiop_ffi.cpp
    )

    # Link against the libraries found by PkgConfig.
    target_link_libraries(libiop_ffi PRIVATE
        iop
        ff
        ${SODIUM_LIBRARIES}
        ${GMP_LIBRARIES}
    )

    if(WIN32)
        set_target_properties(libiop_ffi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif()
endif()
