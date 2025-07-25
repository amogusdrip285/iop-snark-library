cmake_minimum_required(VERSION 3.1) #[cite: 1]

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_VERSION 0.2.0)
project (libiop
  DESCRIPTION "Library for building IOP based SNARKs"
  LANGUAGES CXX C)

# --- START OF NEW/MODIFIED CONFIGURATION ---

# Ensure all targets compile with Position Independent Code (PIC)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find PkgConfig first
find_package(PkgConfig REQUIRED)

# Use PkgConfig to find Libsodium for native Linux build
# This will set SODIUM_INCLUDE_DIRS and SODIUM_LIBRARIES
pkg_check_modules(SODIUM REQUIRED libsodium)

# Include Libsodium headers (from pkg-config)
include_directories(${SODIUM_INCLUDE_DIRS})

# --- END OF NEW/MODIFIED CONFIGURATION ---

# Performance options
option(PERFORMANCE "Enable link-time and aggressive optimizations" OFF) #[cite: 1]
option(MULTICORE "Enable parallelized execution, using OpenMP" OFF) #[cite: 1]
option(USE_ASM "Use architecture-specific optimized assembly code" ON) #[cite: 1]
option(
  ASM_MINIMIZE_CLMULS
  "When USE_ASM is on, minimize the number of CLMUL instructions in binary fields (for CPUs where CLMUL is slow)"
  OFF
) #[cite: 1]

set(
  OPT_FLAGS
  ""
  CACHE
  STRING
  "Override C++ compiler optimization flags"
) #[cite: 1]

# Profiling
option(WITH_PROCPS "Use procps for memory profiling" OFF) #[cite: 1]
# TODO: Expose the libff opcount flag here

# Debugging flags
option(DEBUG "Enable debugging mode" OFF) #[cite: 1]
option(CPPDEBUG "Enable debugging of C++ STL (does not imply DEBUG)" OFF) #[cite: 2]
# Should these be part of DEBUG/CPPDebug?
option(USE_ASAN "Enable Clang address sanitizer" OFF) #[cite: 3]
option(USE_UBSAN "Enable Clang undefined behavior sanitizer" OFF) #[cite: 3]


if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang") #[cite: 3]
  # Common compilation flags and warning configuration
  # TODO: upstream -Wno-... patches in libff, libfqfft
  set(DISABLED_WARNINGS
    "-Wno-sign-compare -Wno-shadow -Wno-unused-variable -Wno-unused-parameter"
    ) #[cite: 3]
  set(DISABLED_WARNINGS_CLANG
    "-Wno-delete-non-virtual-dtor"
    ) #[cite: 3]
  set(DISABLED_WARNINGS_NOT_CLANG
    "-Wno-unused-but-set-variable"
    ) #[cite: 3]
  set(
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -Wfatal-errors ${DISABLED_WARNINGS} -L/usr/local/lib"
    ) #[cite: 3]
  # Default optimizations flags (to override, use -DOPT_FLAGS=...)
  if("${OPT_FLAGS}" STREQUAL "") #[cite: 3]
    set(
      OPT_FLAGS
      "-ggdb3 -O3 -march=native -mtune=native"
    ) #[cite: 4]
  endif()
endif() #[cite: 4]

set(
  CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}"
) #[cite: 4]

# TODO: figure out a fix and unsilence this
if(CMAKE_CXX_COMPILER_ID STREQUAL Clang) #[cite: 4]
  set(
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} ${DISABLED_WARNINGS_CLANG}"
    ) #[cite: 4]
else()
  set(
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} ${DISABLED_WARNINGS_NOT_CLANG}"
    ) #[cite: 4]
endif() #[cite: 4]

enable_testing() #[cite: 4]

if("${DEBUG}") #[cite: 4]
  add_definitions(-DDEBUG) #[cite: 4]
endif() #[cite: 4]

if("${MULTICORE}") #[cite: 4]
  add_definitions(-DMULTICORE) #[cite: 4]
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp") #[cite: 4]
endif() #[cite: 4]

if("${CPPDEBUG}") #[cite: 4]
  add_definitions(-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC -DCPPDEBUG) #[cite: 4]
endif() #[cite: 4]

if("${USE_ASAN}" OR "${USE_UBSAN}") #[cite: 4]
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang") #[cite: 4]
    if("${USE_ASAN}") #[cite: 4]
      set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize-address-use-after-scope") #[cite: 5]
    endif() #[cite: 5]
    if("${USE_UBSAN}") #[cite: 5]
      set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -fsanitize=integer,undefined") #[cite: 5]
    endif() #[cite: 5]
    set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer") #[cite: 5]
  else()
    message(SEND_ERROR "libstark make files only have sanitizer support for clang. Patches welcome!") #[cite: 6]
  endif()
endif() #[cite: 6]

if("${PERFORMANCE}") #[cite: 6]
  add_definitions(-DNDEBUG) #[cite: 6]
  if(CMAKE_CXX_COMPILER_ID STREQUAL GNU) #[cite: 6]
    set(CMAKE_AR gcc-ar) #[cite: 6]
    set(CMAKE_RANLIB gcc-ranlib) #[cite: 6]
  endif() #[cite: 6]
  set(
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -flto -Wno-unused-variable -Wno-lto-type-mismatch"
    ) #[cite: 6]
  set(
    CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -flto"
    ) #[cite: 6]
  set(BENCHMARK_ENABLE_LTO ON CACHE BOOL "Enable link time optimisation of the benchmark library.") #[cite: 6]
endif() #[cite: 6]

if("${USE_ASM}") #[cite: 6]
  add_definitions(-DUSE_ASM) #[cite: 6]
  if("${ASM_MINIMIZE_CLMULS}") #[cite: 6]
    add_definitions(-DASM_MINIMIZE_CLMULS) #[cite: 6]
  endif() #[cite: 6]
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mpclmul -msse4.1") #[cite: 6]
endif() #[cite: 6]

# Enable Boost for program_options
if("${CPPDEBUG}") #[cite: 6]
else()
  FIND_PACKAGE( Boost 1.40 COMPONENTS program_options REQUIRED ) #[cite: 6]
  INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} ) #[cite: 6]
endif() #[cite: 6]

# Configure CCache if available #[cite: 7]
find_program(CCACHE_FOUND ccache) #[cite: 7]
if(CCACHE_FOUND) #[cite: 7]
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache) #[cite: 7]
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache) #[cite: 7]
endif(CCACHE_FOUND) #[cite: 7]

# Add a `make check` target that builds and tests
enable_testing() #[cite: 7]
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND}) #[cite: 7]

include_directories(.) #[cite: 7]

add_subdirectory(depends) #[cite: 7]
add_subdirectory(libiop) #[cite: 7]

# ===================================================================
# FFI Shared Library Target
# ===================================================================

# Create a new shared library target for the FFI wrapper. #[cite: 8]
# This will produce 'libiop_ffi.so' on Linux/WSL. #[cite: 8]
add_library(libiop_ffi SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/ffi/libiop_ffi.cpp
) #[cite: 8]

# Explicitly ensure that 'iop' and 'ff' targets are built before 'libiop_ffi'
# Assuming the actual target names are 'iop' and 'ff' from their respective CMakeLists.txt
add_dependencies(libiop_ffi iop ff)

# Tell the compiler where to find the FFI header files. #[cite: 9]
target_include_directories(libiop_ffi PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/ffi #[cite: 9]
    ${CMAKE_CURRENT_SOURCE_DIR}/depends/libfqfft #[cite: 9]
    ${CMAKE_CURRENT_SOURCE_DIR}/depends/libff #[cite: 9]
    ${CMAKE_CURRENT_SOURCE_DIR}/depends/gtest/googletest/include #[cite: 9]
    ${CMAKE_CURRENT_SOURCE_DIR}/depends/gtest/googlemock/include #[cite: 9]
    # REMOVED: /mnt/d/vcpkg/installed/x64-windows/include (This path is for Windows targets)
)

# REMOVED: target_compile_definitions(libiop_ffi PRIVATE _WIN32) (This definition is for Windows targets)

# Link your FFI library against the main libiop library and its dependencies. #[cite: 10]
# These targets (libiop, libff, etc.) are created by the add_subdirectory calls above. #[cite: 10]
target_link_libraries(libiop_ffi PRIVATE
    iop # Changed from libiop to the target name 'iop'
    ff  # Changed from libff to the target name 'ff'
    ${SODIUM_LIBRARIES} # Link using the variable set by pkg_check_modules
    gmp
) #[cite: 11]