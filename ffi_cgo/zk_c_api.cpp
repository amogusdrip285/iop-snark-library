// ffi_cgo/zk_c_api.cpp
#include "libiop_ffi.h"
#include <cstdint>
#include <cstdlib>

extern "C" {

// Forward declarations of the object-based C API implemented in ffi/libiop_ffi.cpp
// These come from libiop_ffi.h, but redeclare here with C linkage to be explicit.
struct proof_handle_t;
void set_r1cs_input_values(uint64_t a, uint64_t b, uint64_t const_val);
proof_handle_t* generate_r1cs_proof_obj(void);
bool verify_r1cs_proof_obj(proof_handle_t* handle);
void free_proof_obj(proof_handle_t* handle);

// Simple wrappers with names used by Go bindings
bool zk_set_inputs(uint64_t a, uint64_t b, uint64_t const_val) {
    set_r1cs_input_values(a, b, const_val);
    return true;
}

// return the opaque pointer to the caller as void*
void* zk_generate_proof_obj() {
    proof_handle_t* h = generate_r1cs_proof_obj();
    return reinterpret_cast<void*>(h);
}

bool zk_verify_proof_obj(void* h) {
    if (h == nullptr) return false;
    proof_handle_t* ph = reinterpret_cast<proof_handle_t*>(h);
    return verify_r1cs_proof_obj(ph);
}

void zk_free_proof_obj(void* h) {
    if (h == nullptr) return;
    proof_handle_t* ph = reinterpret_cast<proof_handle_t*>(h);
    free_proof_obj(ph);
}

// Returns proof as raw bytes via malloc
bool zk_generate_proof_bytes(uint8_t** out_buf, size_t* out_len) {
    return generate_r1cs_proof_bytes(out_buf, out_len);
}

bool zk_verify_proof_bytes(const uint8_t* buf, size_t len) {
    return verify_r1cs_proof_bytes(buf, len);
}

} // extern "C"
