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

//Node API
#include <napi.h>

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

// =============================================================================
// Node.js N-API Registration Layer
// This part "adapts" the C-style FFI functions above for Node.js.
// =============================================================================

/**
 * @brief N-API wrapper for generate_r1cs_proof_obj.
 * It calls the original function and wraps the returned handle in a special
 * JavaScript-aware object (Napi::External) that can be passed around safely.
 */
Napi::Value GenerateProofWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Call your existing C-style function
    proof_handle_t* handle = generate_r1cs_proof_obj();

    if (handle == nullptr) {
        Napi::Error::New(env, "Proof generation failed in native library (returned null handle).").ThrowAsJavaScriptException();
        return env.Null();
    }

    // This is a C++ lambda function that will be called automatically by the
    // JavaScript garbage collector when the proof object is no longer in use.
    // It prevents memory leaks by calling your existing free_proof_obj function.
    auto finalizer = [](Napi::Env env, proof_handle_t* handle_to_delete) {
        std::cout << "Node.js garbage collector is freeing the proof object." << std::endl;
        free_proof_obj(handle_to_delete);
    };

    // Wrap the raw C++ handle in a Napi::External object and attach the finalizer.
    return Napi::External<proof_handle_t>::New(env, handle, finalizer);
}

/**
 * @brief N-API wrapper for verify_r1cs_proof_obj.
 * It unwraps the handle from the Napi::External object and passes it
 * to your original C-style verification function.
 */
Napi::Value VerifyProofWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsExternal()) {
        Napi::TypeError::New(env, "A proof handle is expected as the first argument.").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Unwrap the proof_handle_t* from the JavaScript object.
    proof_handle_t* handle = info[0].As<Napi::External<proof_handle_t>>().Data();

    // Call your existing C-style function.
    bool is_valid = verify_r1cs_proof_obj(handle);

    // Return the result as a JavaScript boolean.
    return Napi::Boolean::New(env, is_valid);
}

/**
 * @brief N-API wrapper for your manual free_proof_obj function.
 * Note: While this is provided, relying on the automatic garbage collection
 * (the finalizer above) is generally safer to prevent memory leaks.
 */
void FreeProofWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

     if (info.Length() < 1 || !info[0].IsExternal()) {
        Napi::TypeError::New(env, "A proof handle is expected as the first argument.").ThrowAsJavaScriptException();
        return;
    }

    // Unwrap the proof_handle_t* from the JavaScript object.
    proof_handle_t* handle = info[0].As<Napi::External<proof_handle_t>>().Data();
    
    // Call your existing C-style function.
    free_proof_obj(handle);
    
    // Note: It's important not to use the JavaScript handle again after this,
    // as the underlying memory is now gone.
}


/**
 * @brief This `Init` function is the required entry point for the Node.js addon.
 * It's where you define what your module exports to JavaScript.
 */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Set the properties on the `exports` object, mapping a JS name
    // to the N-API wrapper functions we just defined.
    exports.Set("generate_r1cs_proof_obj", Napi::Function::New(env, GenerateProofWrapper));
    exports.Set("verify_r1cs_proof_obj", Napi::Function::New(env, VerifyProofWrapper));
    exports.Set("free_proof_obj", Napi::Function::New(env, FreeProofWrapper));

    return exports;
}

/**
 * @brief This macro is the magic that registers the module with Node.js,
 * solving the "Module did not self-register" error.
 */
NODE_API_MODULE(addon, Init)