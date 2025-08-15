cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_VERSION 0.2.0)
project (libiop
  DESCRIPTION "Library for building IOP based SNARKs"
  LANGUAGES CXX C)

if(DEFINED ENV{VCPKG_ROOT} AND IS_DIRECTORY $ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

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
    # Force the portable ALT_BN128 curve on Windows.
    set(CURVE "ALT_BN128" CACHE STRING "Set curve to ALT_BN128 for Windows compatibility" FORCE)
    # The USE_ASM option enables GCC/Clang-specific intrinsics that fail on MSVC.
    set(USE_ASM OFF CACHE BOOL "Disable assembly on Windows for compatibility" FORCE)
else()
    # On non-Windows platforms, set a valid portable curve.
    set(CURVE "ALT_BN128" CACHE STRING "Set curve to ALT_BN128 for compatibility" FORCE)
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

enable_testing()

# Add back the "make check" target
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ffi_test
)

include_directories(.)

# --- Add Subdirectories ---
add_subdirectory(depends)

target_sources(ff PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/depends/libff/libff/algebra/fields/binary/gf64.cpp
)

add_subdirectory(libiop)

# ===================================================================
# FFI Target for Native Node.js Addon (for cmake-js)
# ===================================================================
if(CMAKE_JS_INC)
	message(STATUS "Configuring Native Node.js Addon target")

	if(NOT CMAKE_JS_PLATFORM_MODULE_NAME)
 	   set(CMAKE_JS_PLATFORM_MODULE_NAME "addon")
	endif()

	# Create the shared library target.
	# CMAKE_JS_PLATFORM_MODULE_NAME is a variable provided by cmake-js
	# that ensures the output file is named correctly (e.g., addon.node).
	add_library(${CMAKE_JS_PLATFORM_MODULE_NAME} SHARED
	    ${CMAKE_CURRENT_SOURCE_DIR}/ffi/libiop_ffi.cpp
	    ${CMAKE_CURRENT_SOURCE_DIR}/ffi/addon.cpp
	)
	
	set_target_properties(${CMAKE_JS_PLATFORM_MODULE_NAME} PROPERTIES
	    PREFIX ""
	    SUFFIX ".node"
	)
	
	# Add include directories
	target_include_directories(${CMAKE_JS_PLATFORM_MODULE_NAME} PUBLIC
	    ${CMAKE_CURRENT_SOURCE_DIR}/ffi
	    ${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-addon-api
	    ${NODE_INCLUDE_DIRS}
	    ${CMAKE_JS_INC}
	    ${NODE_ADDON_API_INCLUDES}
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
endif()

# ===================================================================
# Test Target for ffi/main_test.cpp
# ===================================================================

# Option to control whether the test executable is built
option(BUILD_FFI_TEST "Build the main_test.cpp FFI executable" ON)

if(BUILD_FFI_TEST)
    message(STATUS "Configuring ffi_test executable target")

    # Define the executable target from BOTH its source files.
    add_executable(ffi_test
        ffi/main_test.cpp
        ffi/libiop_ffi.cpp
    )

    # The test needs to find the libiop_ffi.h header.
    target_include_directories(ffi_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ffi
    )

    # Link ffi_test directly against its C++ dependencies.
    # We DO NOT link against addon.node here.
    target_link_libraries(ffi_test PRIVATE
        iop
        ff
        ${SODIUM_LIBRARIES}
        ${GMP_LIBRARIES}
        ${Boost_LIBRARIES}
    )
endif()

# ===================================================================
# Shared library target for Go cgo integration
# ===================================================================

option(BUILD_GO_FFI "Build Go FFI shared library" ON)

if(BUILD_GO_FFI)
    message(STATUS "Configuring zkffi_wrapper shared library target for Go")

    add_library(zkffi_wrapper SHARED
        ffi_cgo/zk_c_api.cpp
        ffi/libiop_ffi.cpp
    )

    target_include_directories(zkffi_wrapper PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/ffi
        ${CMAKE_CURRENT_SOURCE_DIR}/ffi_cgo
    )

    target_link_libraries(zkffi_wrapper PRIVATE
        iop
        ff
        ${SODIUM_LIBRARIES}
        ${GMP_LIBRARIES}
        ${Boost_LIBRARIES}
        stdc++ pthread
    )

    # On Unix, will output libzkffi_wrapper.so in build dir
    # On Windows, will output zkffi_wrapper.dll
    if(WIN32)
        set_target_properties(zkffi_wrapper PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif()
	# Install the shared library system-wide
	install(TARGETS zkffi_wrapper
	    LIBRARY DESTINATION /usr/local/lib
	)

	# Optional: also install the header so Go FFI can include it
	install(FILES ${CMAKE_SOURCE_DIR}/libiop/zk_c_api.h
	    DESTINATION /usr/local/include
	)
endif()


