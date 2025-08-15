#include "libiop_ffi.h"
#include <napi.h>

// =============================================================================
// Node.js N-API Registration Layer
// Updated: No buffer_t, uses global_example in native code
// =============================================================================

Napi::Value GenerateProofWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // No arguments needed — everything is set in native global_example
    proof_handle_t* handle = generate_r1cs_proof_obj();

    if (handle == nullptr) {
        Napi::Error::New(env, "Proof generation failed in native library.")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    auto finalizer = [](Napi::Env env, proof_handle_t* h) {
        free_proof_obj(h);
    };

    return Napi::External<proof_handle_t>::New(env, handle, finalizer);
}

Napi::Value VerifyProofWrapper(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsExternal()) {
        Napi::TypeError::New(env, "Expected a proof handle")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    proof_handle_t* handle =
        info[0].As<Napi::External<proof_handle_t>>().Data();

    bool is_valid = verify_r1cs_proof_obj(handle);

    return Napi::Boolean::New(env, is_valid);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("generateProof", Napi::Function::New(env, GenerateProofWrapper));
    exports.Set("verifyProof", Napi::Function::New(env, VerifyProofWrapper));
    return exports;
}

NODE_API_MODULE(addon, Init)
