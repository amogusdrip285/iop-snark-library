import ctypes
import os

def main():
    """
    This script demonstrates how to call the FFI functions from the compiled
    libiop_ffi.so library using Python's ctypes module.
    It uses opaque pointers to safely handle complex C++ objects.
    """
    # --- 1. Load the Shared Library ---
    try:
        # Assumes the script is run from the root of the libiop directory
        lib_path = os.path.join(os.getcwd(), "build", "liblibiop_ffi.so")
        libiop = ctypes.CDLL(lib_path)
    except OSError as e:
        print(f"Error loading shared library: {e}")
        print(f"Attempted to load from: {lib_path}")
        print("Please ensure that 'liblibiop_ffi.so' is in the 'build' directory.")
        return

    # --- 2. Define Function Signatures (Prototypes) ---
    # An opaque pointer is represented as c_void_p
    proof_handle_p = ctypes.c_void_p

    # proof_handle_t* generate_r1cs_proof_obj()
    libiop.generate_r1cs_proof_obj.argtypes = []
    libiop.generate_r1cs_proof_obj.restype = proof_handle_p

    # bool verify_r1cs_proof_obj(proof_handle_t*)
    libiop.verify_r1cs_proof_obj.argtypes = [proof_handle_p]
    libiop.verify_r1cs_proof_obj.restype = ctypes.c_bool

    # void free_proof_obj(proof_handle_t*)
    libiop.free_proof_obj.argtypes = [proof_handle_p]
    libiop.free_proof_obj.restype = None

    print("--- Python FFI Test Started ---")

    # --- 3. Call the FFI Functions ---
    proof_handle = None
    try:
        print("\nStep 1: Calling generate_r1cs_proof_obj from Python...")
        proof_handle = libiop.generate_r1cs_proof_obj()

        if not proof_handle:
            print("Proof generation FAILED: C++ function returned a null pointer.")
            return

        print("Proof generation successful. Received proof handle.")

        # --- 4. Verify the Proof ---
        print("\nStep 2: Calling verify_r1cs_proof_obj from Python...")
        is_valid = libiop.verify_r1cs_proof_obj(proof_handle)

        if is_valid:
            print("Verification SUCCEEDED.")
        else:
            print("Verification FAILED.")

    finally:
        # --- 5. Free the Memory ---
        # This is critical. It ensures the C++ memory is freed even if verification fails.
        if proof_handle:
            print("\nStep 3: Calling free_proof_obj to clean up memory...")
            libiop.free_proof_obj(proof_handle)
            print("Memory freed.")

    print("\n--- Python FFI Test Finished ---")

if __name__ == "__main__":
    main()
