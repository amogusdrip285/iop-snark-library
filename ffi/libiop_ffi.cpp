#include "libiop_ffi.h"

// C++ Standard Library
#include <iostream>
#include <memory>
#include <vector>
#include <cstring>

// Include the main header for libsodium to resolve path issues.
#include <sodium.h>

// libiop components
#include "libiop/snark/aurora_snark.hpp"
#include "libiop/relations/examples/r1cs_examples.hpp"
#include "libiop/bcs/bcs_common.hpp"

// libff dependencies
#include <libff/algebra/fields/binary/gf64.hpp>

// Define a concrete FieldType and HashType to make the code non-templated
using FieldT = libff::gf64;
using HashT = libiop::binary_hash_digest;

// Define the proof object type for convenience
using ProofT = libiop::aurora_snark_argument<FieldT, HashT>;

// =============================================================================
// FIX: Create a truly global, static R1CS instance.
// This is initialized only once when the library is loaded, guaranteeing
// that the prover and verifier use the exact same problem data.
// =============================================================================
libiop::r1cs_example<FieldT> create_global_r1cs_example() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed!");
    }
    const size_t num_constraints = 1 << 10;
    const size_t num_inputs = (1 << 4) - 1;
    const size_t num_variables = (1 << 10) - 1;
    return libiop::generate_r1cs_example<FieldT>(num_constraints, num_inputs, num_variables);
}

static const libiop::r1cs_example<FieldT> global_example = create_global_r1cs_example();


// Helper function to create a default set of parameters for the Aurora SNARK
libiop::aurora_snark_parameters<FieldT, HashT> get_default_aurora_parameters(
    const size_t num_constraints,
    const size_t num_variables,
    const bool make_zk)
{
    const size_t security_parameter = 128;
    const size_t RS_extra_dimensions = 2;
    const size_t FRI_localization_parameter = 3;
    const libiop::LDT_reducer_soundness_type ldt_reducer_soundness_type = libiop::LDT_reducer_soundness_type::optimistic_heuristic;
    const libiop::FRI_soundness_type fri_soundness_type = libiop::FRI_soundness_type::heuristic;
    const libiop::field_subset_type domain_type = libiop::affine_subspace_type;

    return libiop::aurora_snark_parameters<FieldT, HashT>(
        security_parameter,
        ldt_reducer_soundness_type,
        fri_soundness_type,
        libiop::blake2b_type,
        FRI_localization_parameter,
        RS_extra_dimensions,
        make_zk,
        domain_type,
        num_constraints,
        num_variables);
}

// FFI Implementation
#ifdef __cplusplus
extern "C" {
#endif

// This is our opaque handle. The C/Python side only knows it's a pointer.
struct proof_handle_t {
    ProofT* proof;
};

API_EXPORT proof_handle_t* generate_r1cs_proof_obj()
{
    try {
        if (!global_example.constraint_system_.is_satisfied(global_example.primary_input_, global_example.auxiliary_input_)) {
            std::cerr << "Error: Global R1CS example is not satisfied!" << std::endl;
            return nullptr;
        }

        const bool make_zk = true;
        libiop::aurora_snark_parameters<FieldT, HashT> params =
            get_default_aurora_parameters(global_example.constraint_system_.num_constraints(), global_example.constraint_system_.num_variables(), make_zk);

        std::cout << "Generating proof object..." << std::endl;
        
        // Allocate the proof on the heap with 'new'
        ProofT* proof_ptr = new ProofT(libiop::aurora_snark_prover<FieldT, HashT>(
                global_example.constraint_system_,
                global_example.primary_input_,
                global_example.auxiliary_input_,
                params));
        
        std::cout << "Proof generation complete." << std::endl;

        // Create a handle and return it
        proof_handle_t* handle = new proof_handle_t();
        handle->proof = proof_ptr;
        return handle;

    } catch (const std::exception& e) {
        std::cerr << "An exception occurred during proof generation: " << e.what() << std::endl;
        return nullptr;
    }
}

API_EXPORT bool verify_r1cs_proof_obj(proof_handle_t* proof_handle)
{
    if (proof_handle == nullptr || proof_handle->proof == nullptr) {
        return false;
    }

    try {
        const bool make_zk = true;
        libiop::aurora_snark_parameters<FieldT, HashT> params =
            get_default_aurora_parameters(global_example.constraint_system_.num_constraints(), global_example.constraint_system_.num_variables(), make_zk);

        std::cout << "Verifying proof object..." << std::endl;
        
        // Use the proof from the handle
        const bool result = libiop::aurora_snark_verifier<FieldT, HashT>(
            global_example.constraint_system_,
            global_example.primary_input_,
            *(proof_handle->proof),
            params);
            
        std::cout << "Verification complete." << std::endl;
        return result;

    } catch (const std::exception& e) {
        std::cerr << "An exception occurred during verification: " << e.what() << std::endl;
        return false;
    }
}

API_EXPORT void free_proof_obj(proof_handle_t* proof_handle) {
    if (proof_handle != nullptr) {
        delete proof_handle->proof; // Delete the C++ proof object
        delete proof_handle;       // Delete the handle itself
    }
}

#ifdef __cplusplus
}
#endif