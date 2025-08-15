cmake_minimum_required(VERSION 3.10)
project(zkffi_wrapper CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Make sure CMake can find your project's headers; adjust if your repo layout differs.
include_directories(${CMAKE_SOURCE_DIR})    # top-level repo
include_directories(${CMAKE_SOURCE_DIR}/libiop) # if you keep libiop includes there

# Compile the wrapper into a shared library. Link against any libraries your project needs.
add_library(zkffi_wrapper SHARED
    zk_c_api.cpp
)

# Link the wrapper with the main project object/library that defines generate_r1cs_proof_obj, etc.
# If your main project already builds a library (e.g., libiopffi), link to it:
target_link_libraries(zkffi_wrapper PRIVATE libiopffi)
#
# If you don't have a prebuilt lib, you can also compile the repo's FFI source
# into this target by adding the relevant .cpp files here (not ideal for large projects).
#
# You will almost certainly need to link libsodium, pthread, stdc++, and others:
target_link_libraries(zkffi_wrapper PRIVATE stdc++ pthread sodium)
#
# If your project needs other link flags (gmp, libff, libiop static libs), add them:
# target_link_libraries(zkffi_wrapper PRIVATE /path/to/libiop.a /path/to/libff.a ...)
