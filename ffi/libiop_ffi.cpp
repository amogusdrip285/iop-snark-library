#include "libiop_ffi.h"
#include <cstdint>
#include <type_traits>
#include <sstream>

#include <unordered_map>
#include <atomic>
#include <mutex>


#include <libff/algebra/fields/binary/gf64.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "libiop/algebra/polynomials/polynomial.hpp"
#include "libiop/iop/iop.hpp"
#include "libiop/tests/bcs/dummy_bcs_protocol.hpp"
#include "libiop/bcs/bcs_prover.hpp"
#include "libiop/bcs/bcs_indexer.hpp"
#include "libiop/bcs/bcs_verifier.hpp"
#include "libiop/bcs/hashing/blake2b.hpp"
#include "libiop/bcs/hashing/dummy_algebraic_hash.hpp"
#include "libiop/snark/aurora_snark.hpp"
#include "libiop/relations/examples/r1cs_examples.hpp"

#include <libff/common/serialization.hpp>

// C++ Standard Library
#include <iostream>
#include <memory>
#include <vector>
#include <cstring>
#include <sstream>

// libsodium
#include <sodium.h>

// libiop components 
#include "libiop/bcs/bcs_common.hpp"

namespace {
    std::mutex g_mtx;
    std::unordered_map<uint64_t, proof_handle_t*> g_registry;
    std::atomic<uint64_t> g_next_id{1};
}


static uint64_t g_a_val = 0;
static uint64_t g_b_val = 0;
static uint64_t g_const_val = 0;

extern "C" void set_r1cs_input_values(uint64_t a, uint64_t b, uint64_t const_val) {
    g_a_val = a;
    g_b_val = b;
    g_const_val = const_val;
}

// Define a concrete FieldType and HashType to make the code non-templated
using FieldT = libff::gf64;
using HashT  = libiop::binary_hash_digest;
using ProofT = libiop::aurora_snark_argument<FieldT, HashT>;

// Build a new R1CS example using current g_a_val, g_b_val, g_const_val
static libiop::r1cs_example<FieldT> create_r1cs_example_from_globals()
{
    const uint64_t CONST_VAL = g_const_val;
    const uint64_t A_val     = g_a_val;
    const uint64_t B_val     = g_b_val;

    libiop::r1cs_example<FieldT> example;

    auto var_lc = [&](size_t idx, const FieldT &coeff = FieldT::one()) {
        libiop::linear_combination<FieldT> lc;
        lc.add_term(idx, coeff);
        return lc;
    };

    // Constraint 0: a * b = c
    {
        auto A = var_lc(2);
        auto B = var_lc(3);
        auto C = var_lc(4);
        example.constraint_system_.add_constraint(
            libiop::r1cs_constraint<FieldT>(A, B, C)
        );
    }

    // Constraint 1: c + CONST_VAL = out
    {
        libiop::linear_combination<FieldT> A; 
        A.add_term(0, FieldT::one());

        libiop::linear_combination<FieldT> B = var_lc(4);
        B.add_term(0, FieldT(CONST_VAL));

        libiop::linear_combination<FieldT> C = var_lc(1);
        example.constraint_system_.add_constraint(
            libiop::r1cs_constraint<FieldT>(A, B, C)
        );
    }

    // Witness
    FieldT a   = FieldT(A_val);
    FieldT b   = FieldT(B_val);
    FieldT c   = a * b;
    FieldT out = c + FieldT(CONST_VAL);

    example.primary_input_.clear();
    example.primary_input_.push_back(out);

    example.auxiliary_input_.clear();
    example.auxiliary_input_.push_back(a);
    example.auxiliary_input_.push_back(b);
    example.auxiliary_input_.push_back(c);

    // Padding to power-of-two variables
    size_t cur_vars = example.primary_input_.size() + example.auxiliary_input_.size();
    size_t k = 0;
    while (((size_t(1) << k) - 1) < cur_vars) ++k;
    size_t target_vars = (size_t(1) << k) - 1;
    size_t pad = (target_vars > cur_vars) ? (target_vars - cur_vars) : 0;
    for (size_t i = 0; i < pad; ++i) {
        example.auxiliary_input_.push_back(FieldT::zero());
    }

    example.constraint_system_.primary_input_size_   = example.primary_input_.size();
    example.constraint_system_.auxiliary_input_size_ = example.auxiliary_input_.size();

    return example;
}

static libiop::aurora_snark_parameters<FieldT, HashT> get_default_aurora_parameters(
    const size_t num_constraints,
    const size_t num_variables)
{
    const size_t security_parameter = 128;
    const bool make_zk = true;
    const size_t RS_extra_dimensions = 2;
    const size_t FRI_localization_parameter = 3;
    const libiop::LDT_reducer_soundness_type ldt_soundness_type =
        libiop::LDT_reducer_soundness_type::optimistic_heuristic;
    const libiop::FRI_soundness_type fri_soundness_type = libiop::FRI_soundness_type::heuristic;
    const libiop::field_subset_type domain_type = libiop::affine_subspace_type;

    return libiop::aurora_snark_parameters<FieldT, HashT>(
        security_parameter,
        ldt_soundness_type,
        fri_soundness_type,
        libiop::blake2b_type,
        FRI_localization_parameter,
        RS_extra_dimensions,
        make_zk,
        domain_type,
        num_constraints,
        num_variables);
}

extern "C" {

struct proof_handle_t {
    ProofT* proof;
    libiop::r1cs_example<FieldT>* example;
};

API_EXPORT proof_handle_t* generate_r1cs_proof_obj() {
    auto example = new libiop::r1cs_example<FieldT>(create_r1cs_example_from_globals());
    auto params = get_default_aurora_parameters(
        example->constraint_system_.num_constraints(),
        example->constraint_system_.num_variables()
    );

    auto proof = new ProofT(libiop::aurora_snark_prover<FieldT, HashT>(
        example->constraint_system_,
        example->primary_input_,
        example->auxiliary_input_,
        params
    ));

    auto handle = new proof_handle_t{proof, example};
    return handle;
}

API_EXPORT bool verify_r1cs_proof_obj(proof_handle_t* handle) {
    if (!handle) return false;
    auto params = get_default_aurora_parameters(
        handle->example->constraint_system_.num_constraints(),
        handle->example->constraint_system_.num_variables()
    );

    return libiop::aurora_snark_verifier<FieldT, HashT>(
        handle->example->constraint_system_,
        handle->example->primary_input_,
        *handle->proof,
        params
    );
}

API_EXPORT void free_proof_obj(proof_handle_t* handle) {
    if (!handle) return;
    delete handle->proof;
    delete handle->example;
    delete handle;
}

extern "C" API_EXPORT bool generate_r1cs_proof_bytes(uint8_t** out_buf, size_t* out_len) {
    if (!out_buf || !out_len) return false;

    // Use your existing object API to build a proof object
    proof_handle_t* h = generate_r1cs_proof_obj();
    if (!h) return false;

    // Assign an id and stash the handle
    uint64_t id = g_next_id++;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        g_registry[id] = h;
    }

    // Return the id as 8 bytes (little-endian)
    uint8_t* mem = static_cast<uint8_t*>(std::malloc(sizeof(uint64_t)));
    if (!mem) return false;
    std::memcpy(mem, &id, sizeof(uint64_t));
    *out_buf = mem;
    *out_len = sizeof(uint64_t);
    return true;
}

extern "C" API_EXPORT bool verify_r1cs_proof_bytes(const uint8_t* buf, size_t len) {
    if (!buf || len != sizeof(uint64_t)) return false;

    uint64_t id = 0;
    std::memcpy(&id, buf, sizeof(uint64_t));

    proof_handle_t* h = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        auto it = g_registry.find(id);
        if (it == g_registry.end()) return false;
        h = it->second;
        g_registry.erase(it);
    }

    const bool ok = verify_r1cs_proof_obj(h);
    free_proof_obj(h); // free after verify
    return ok;
}

// already OK, but ensure it exists and uses std::free
extern "C" API_EXPORT void free_buffer(uint8_t* p) {
    if (p) std::free(p);
}

} // extern "C"
