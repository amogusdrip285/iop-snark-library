# This file is located at depends/CMakeLists.txt

# On Windows, we do not build any of the submodules that conflict with vcpkg
# or are incompatible with the MSVC compiler.
if(NOT WIN32)
    add_subdirectory(gtest EXCLUDE_FROM_ALL)
    add_subdirectory(benchmark)

    # The ate-pairing library is incompatible with MSVC.
    include_directories(ate-pairing/include)
    include_directories(xbyak)
    add_library(
            zm
            STATIC
            ate-pairing/src/zm.cpp
            ate-pairing/src/zm2.cpp
    )
endif()

# These are compatible and can be included on all platforms
OPTION(IS_LIBFF_PARENT OFF)
add_subdirectory(libff)

OPTION(IS_LIBFQFFT_PARENT OFF)
add_subdirectory(libfqfft)