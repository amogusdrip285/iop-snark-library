#ifndef LIBIOP_FFI_H
#define LIBIOP_FFI_H

#include <stddef.h>
#include <stdbool.h>
#include <chrono>
#include <stdint.h>
#include <sstream>


#ifdef _WIN32
  #define API_EXPORT __declspec(dllexport)
#else
  #define API_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle
struct proof_handle_t;

// Set inputs
API_EXPORT void set_r1cs_input_values(uint64_t a, uint64_t b, uint64_t const_val);

// Existing object-based API
API_EXPORT struct proof_handle_t* generate_r1cs_proof_obj(void);
API_EXPORT bool verify_r1cs_proof_obj(struct proof_handle_t* proof);
API_EXPORT void free_proof_obj(struct proof_handle_t* proof);

// --- NEW: byte-level convenience API for Go (no C++ types) ---
/** Generate a proof and return it as a malloc'ed byte buffer. Caller must free with free_buffer(). */
API_EXPORT bool generate_r1cs_proof_bytes(uint8_t** out_buf, size_t* out_len);

/** Verify a proof directly from bytes. */
API_EXPORT bool verify_r1cs_proof_bytes(const uint8_t* buf, size_t len);

/** Free a buffer previously returned by generate_r1cs_proof_bytes(). */
API_EXPORT void free_buffer(uint8_t* buf);

#ifdef __cplusplus
}
#endif

#endif // LIBIOP_FFI_H