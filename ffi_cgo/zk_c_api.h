#ifndef ZK_C_API_H
#define ZK_C_API_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Set the numeric inputs for the R1CS example (a, b, const)
void set_r1cs_input_values(uint64_t a, uint64_t b, uint64_t const_val);

// Produce a proof into a malloc'd buffer. Returns true on success.
// Caller must call free_buffer on the returned pointer.
bool generate_r1cs_proof_bytes(uint8_t** out_buf, size_t* out_len);

// Verify a proof given as bytes. Returns true if verification succeeded.
bool verify_r1cs_proof_bytes(const uint8_t* buf, size_t len);

// Free a buffer allocated by the above.
void free_buffer(uint8_t* p);

bool zk_set_inputs(uint64_t a, uint64_t b, uint64_t const_val);
bool zk_generate_proof(uint8_t** out_buf, size_t* out_len);
bool zk_verify_proof(const uint8_t* buf, size_t len);
void zk_free_buffer(uint8_t* p);


#ifdef __cplusplus
}
#endif

#endif // ZK_C_API_H
