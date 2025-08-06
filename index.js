const path = require('path');

// 1. Define the path to your compiled C++ addon.
const addonPath = path.join(__dirname, 'build', 'Release', 'addon.node');

// 2. Load the native addon directly using require().
// The `libiop` object will have the functions you exported from C++ using N-API.
const libiop = require(addonPath);

// 3. Wrap the native functions in a user-friendly JavaScript class.
// This part is similar to your original code, but it calls the functions
// from the object loaded by require() instead of from ffi-napi.
class LibIOP {
  constructor() {
    this._proofHandle = null;
  }

  generateProof() {
    console.log('Generating proof...');
    // Call the native function directly.
    this._proofHandle = libiop.generate_r1cs_proof_obj();
    if (!this._proofHandle || this._proofHandle.isNull()) {
      throw new Error('Proof generation failed in the native library.');
    }
    console.log('Proof generation successful.');
  }

  verifyProof() {
    if (!this._proofHandle || this._proofHandle.isNull()) {
      throw new Error('No proof has been generated yet.');
    }
    console.log('Verifying proof...');
    // Call the native function directly.
    const isValid = libiop.verify_r1cs_proof_obj(this._proofHandle);
    console.log(`Verification result: ${isValid}`);
    return isValid;
  }

  freeProof() {
    if (this._proofHandle && !this._proofHandle.isNull()) {
      console.log('Freeing proof memory...');
      // Call the native function directly.
      libiop.free_proof_obj(this._proofHandle);
      this._proofHandle = null;
      console.log('Memory freed.');
    }
  }
}

module.exports = LibIOP;