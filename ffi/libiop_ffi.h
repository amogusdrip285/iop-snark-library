#ifndef LIBIOP_FFI_H
#define LIBIOP_FFI_H

#include <stddef.h> // For size_t
#include <stdbool.h> // For bool

// Define the export macro
#ifdef _WIN32
  #define API_EXPORT __declspec(dllexport)
#else
  #define API_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Define an empty struct to represent the opaque handle.
// The calling language (like Python) only needs to know that this is a pointer.
struct proof_handle_t;

/**
 * @brief Generates a proof object and returns an opaque handle to it.
 * @return A pointer to a proof_handle_t, or NULL on failure.
 * The caller is responsible for freeing this handle using free_proof_obj().
 */
API_EXPORT proof_handle_t* generate_r1cs_proof_obj();

/**
 * @brief Verifies a proof using an opaque handle.
 * @param proof_handle A pointer to the proof_handle_t that was returned by generate_r1cs_proof_obj().
 * @return True if verification succeeds, false otherwise.
 */
API_EXPORT bool verify_r1cs_proof_obj(proof_handle_t* proof_handle);

/**
 * @brief Frees the memory associated with a proof handle.
 * @param proof_handle The handle to free.
 */
API_EXPORT void free_proof_obj(proof_handle_t* proof_handle);

#ifdef __cplusplus
}
#endif

#endif // LIBIOP_FFI_H
