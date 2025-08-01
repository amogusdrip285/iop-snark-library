#include <gtest/gtest.h>
#include <vector>
#include <cmath>
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include "libiop/relations/r1cs.hpp"
#include "libiop/snark/aurora_snark.hpp"

namespace libiop {

TEST(CustomAuroraSnarkTest, FullArithmeticTest) {
    libff::edwards_pp::init_public_params();
    typedef libff::edwards_Fr FieldT;
    typedef binary_hash_digest hash_type;

    /**
     * 1. Define the numbers and calculate the expected witness.
     */
    const FieldT num1(12542);
    const FieldT num2(35512512);
    const FieldT num3(1123);
    const FieldT num4(51252);
    const FieldT num5(13134);

    // Calculate witness values for each step
    const FieldT v1 = num4 * num5;               // Multiplication result
    const FieldT v2 = num1 + num2;               // First addition result
    const FieldT v3 = v2 + num3;                 // Second addition result
    const FieldT final_result = v3 + v1;         // Final result
    const FieldT expected_final_result(708669945);

    /**
     * 2. Set up constraint system dimensions with padding.
     */
    const size_t num_public_inputs = 5;
    const size_t num_aux_real = 4;
    const size_t num_constraints_real = 4;

    const size_t num_inputs_padded = 7;
    const size_t num_input_dummies = num_inputs_padded - num_public_inputs;
    const size_t num_constraints_padded = 4; // 4 is a power of 2

    const size_t num_total_vars_real = num_inputs_padded + num_aux_real; // 7 + 4 = 11
    const size_t num_total_vars_padded = 15; // Next valid size is 15
    const size_t num_aux_dummies = num_total_vars_padded - num_total_vars_real;
    const size_t num_aux_padded = num_aux_real + num_aux_dummies;

    r1cs_constraint_system<FieldT> cs;
    cs.primary_input_size_ = num_inputs_padded;
    cs.auxiliary_input_size_ = num_aux_padded;

    /**
     * 3. Define the 4 constraints explicitly.
     * Variable indices map: 1-5 for public inputs, 8-11 for auxiliary inputs.
     */
    // Constraint 1: v1 = num4 * num5
    linear_combination<FieldT> A1, B1, C1;
    A1.add_term(4, FieldT(1)); // num4 = 51252
    B1.add_term(5, FieldT(1)); // num5 = 13134
    C1.add_term(8, FieldT(1)); // v1
    cs.add_constraint(r1cs_constraint<FieldT>(A1, B1, C1));

    // Constraint 2: v2 = num1 + num2
    linear_combination<FieldT> A2, B2, C2;
    A2.add_term(1, FieldT(1)); // num1
    A2.add_term(2, FieldT(1)); // num2
    B2.add_term(0, FieldT(1)); // constant 1
    C2.add_term(9, FieldT(1)); // v2
    cs.add_constraint(r1cs_constraint<FieldT>(A2, B2, C2));

    // Constraint 3: v3 = v2 + num3
    linear_combination<FieldT> A3, B3, C3;
    A3.add_term(9, FieldT(1)); // v2
    A3.add_term(3, FieldT(1)); // num3
    B3.add_term(0, FieldT(1)); // constant 1
    C3.add_term(10, FieldT(1)); // v3
    cs.add_constraint(r1cs_constraint<FieldT>(A3, B3, C3));

    // Constraint 4: final_result = v3 + v1
    linear_combination<FieldT> A4, B4, C4;
    A4.add_term(10, FieldT(1)); // v3
    A4.add_term(8, FieldT(1));  // v1
    B4.add_term(0, FieldT(1)); // constant 1
    C4.add_term(11, FieldT(1)); // final_result
    cs.add_constraint(r1cs_constraint<FieldT>(A4, B4, C4));

    /**
     * 4. Populate the input vectors with real and dummy values.
     */
    r1cs_primary_input<FieldT> primary_input = {num1, num2, num3, num4, num5};
    for(size_t i = 0; i < num_input_dummies; ++i) primary_input.push_back(FieldT::zero());

    r1cs_auxiliary_input<FieldT> auxiliary_input = {v1, v2, v3, final_result};
    for(size_t i = 0; i < num_aux_dummies; ++i) auxiliary_input.push_back(FieldT::zero());

    ASSERT_TRUE(cs.is_satisfied(primary_input, auxiliary_input));

    /**
     * 5. Configure parameters and run the prover/verifier.
     */
    const bool make_zk = true;
    const size_t security_parameter = 128;
    aurora_snark_parameters<FieldT, binary_hash_digest> params(
        security_parameter, LDT_reducer_soundness_type::optimistic_heuristic, FRI_soundness_type::heuristic,
        blake2b_type, 3, 2, make_zk, multiplicative_coset_type, num_constraints_padded, num_total_vars_padded);

    const aurora_snark_argument<FieldT, binary_hash_digest> argument = aurora_snark_prover<FieldT>(
        cs, primary_input, auxiliary_input, params);

    const bool success = aurora_snark_verifier<FieldT, binary_hash_digest>(
        cs, primary_input, argument, params);

    EXPECT_TRUE(success);
    EXPECT_TRUE(final_result == expected_final_result);
}

} // namespace libiop