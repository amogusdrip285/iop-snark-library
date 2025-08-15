#include "libiop_ffi.h"
#include <iostream>
#include <fstream>

int main() {
    std::cout << "--- Starting R1CS arithmetic test ---" << std::endl;

    std::cout << "Generating proof for: out = 1424124 + 232312 * 13131" << std::endl;
    std::cout << "Running prover (timings will be printed by the native library)..." << std::endl;

    proof_handle_t* proof_handle = generate_r1cs_proof_obj();
    if (proof_handle == nullptr) {
        std::cerr << "Failed to generate proof." << std::endl;
        return 1;
    }
    std::cout << "Proof handle created." << std::endl;

    std::cout << "Verifying proof (timings printed by native library)..." << std::endl;
    bool is_valid = verify_r1cs_proof_obj(proof_handle);

    if (is_valid) {
        std::cout << "\nSUCCESS: Verification successful!" << std::endl;
    } else {
        std::cerr << "\nFAILURE: Verification failed!" << std::endl;
    }

    // Optionally save a little benchmark log file
    std::ofstream out("proof_benchmark.log", std::ios::app);
    if (out) {
        out << (is_valid ? "OK" : "FAIL") << " - proof/verify ran (see stdout for times)\n";
        out.close();
        std::cout << "Also appended a short note to proof_benchmark.log" << std::endl;
    }

    free_proof_obj(proof_handle);

    std::cout << "--- Test finished ---" << std::endl;
    return is_valid ? 0 : 1;
}
