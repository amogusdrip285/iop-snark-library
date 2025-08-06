cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_VERSION 0.2.0)
project (libiop
  DESCRIPTION "Library for building IOP based SNARKs"
  LANGUAGES CXX C)

message(STATUS "--- Node.js Header Debugging ---")
if(NODE_INCLUDE_DIRS)
    message(STATUS "Found NODE_INCLUDE_DIRS: ${NODE_INCLUDE_DIRS}")
    include_directories(${NODE_INCLUDE_DIRS})
endif()
if(CMAKE_JS_INC)
    message(STATUS "Found CMAKE_JS_INC: ${CMAKE_JS_INC}")
    include_directories(${CMAKE_JS_INC})
endif()
message(STATUS "--------------------------------")

# --- Native Dependency Handling ---
message(STATUS "Native build: Searching for system libraries using PkgConfig.")
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMP REQUIRED gmp)
pkg_check_modules(SODIUM REQUIRED libsodium)

# --- Add this block to find and link Boost ---
find_package(Boost REQUIRED COMPONENTS program_options)
include_directories(${Boost_INCLUDE_DIRS})
# -----------------------------------------------

include_directories(${GMP_INCLUDE_DIRS})
include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${GMP_LIBRARY_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})

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

# Add this line to disable building the tests for the benchmark library
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable testing for benchmark" FORCE)

# --- Add Subdirectories ---
add_subdirectory(depends)
add_subdirectory(libiop)

# ===================================================================
# FFI Target for Native Node.js Addon (for cmake-js)
# ===================================================================

message(STATUS "Configuring Native Node.js Addon target")

if(NOT CMAKE_JS_PLATFORM_MODULE_NAME)
    set(CMAKE_JS_PLATFORM_MODULE_NAME "addon")
endif()

# Create the shared library target.
# CMAKE_JS_PLATFORM_MODULE_NAME is a variable provided by cmake-js
# that ensures the output file is named correctly (e.g., addon.node).
add_library(${CMAKE_JS_PLATFORM_MODULE_NAME} SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/ffi/libiop_ffi.cpp
)

set_target_properties(${CMAKE_JS_PLATFORM_MODULE_NAME} PROPERTIES
    PREFIX ""
    SUFFIX ".node"
)

# Add include directories
target_include_directories(${CMAKE_JS_PLATFORM_MODULE_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/ffi
    node_modules/node-addon-api
    ${NODE_INCLUDE_DIRS}
    ${CMAKE_JS_INC}
)

# Link against the libraries found by PkgConfig.
target_link_libraries(${CMAKE_JS_PLATFORM_MODULE_NAME} PRIVATE
    iop
    ff
    ${SODIUM_LIBRARIES}
    ${GMP_LIBRARIES}
    ${Boost_LIBRARIES}
)

if(WIN32)
    set_target_properties(${CMAKE_JS_PLATFORM_MODULE_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()
