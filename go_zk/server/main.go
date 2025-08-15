package main

/*
#cgo LDFLAGS: -L${SRCDIR}/../../build -lzkffi_wrapper -Wl,-rpath,${SRCDIR}/../../build
#include <stdlib.h>
#include <stdint.h>
#include "../../ffi_cgo/zk_c_api.h"
*/
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
	"unsafe"
)

// RPC request/response shapes
type GenerateRequest struct {
	A     uint64 `json:"a"`
	B     uint64 `json:"b"`
	Const uint64 `json:"const"`
}

type GenerateResponse struct {
	ProofBase64 string  `json:"proof_base64"`
	ProverMS    float64 `json:"prover_ms"`
}

type VerifyRequest struct {
	ProofBase64 string `json:"proof_base64"`
}

type VerifyResponse struct {
	Valid      bool    `json:"valid"`
	VerifierMS float64 `json:"verifier_ms"`
}

// JSON RPC endpoints over HTTP
func generateHandler(w http.ResponseWriter, r *http.Request) {
	var req GenerateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	// set inputs
	C.zk_set_inputs(C.uint64_t(req.A), C.uint64_t(req.B), C.uint64_t(req.Const))

	// call generate
	var outBuf *C.uint8_t
	var outLen C.size_t

	start := time.Now()
	ok := C.zk_generate_proof(&outBuf, &outLen)
	elapsed := time.Since(start).Seconds() * 1000.0 // ms

	if ok == false {
		http.Error(w, "proof generation failed", http.StatusInternalServerError)
		return
	}
	defer C.zk_free_buffer(outBuf)

	// copy bytes to Go slice
	length := int(outLen)
	var goBytes []byte
	if length > 0 {
		goBytes = C.GoBytes(unsafe.Pointer(outBuf), C.int(length))
	} else {
		goBytes = []byte{}
	}

	proofB64 := base64.StdEncoding.EncodeToString(goBytes)
	resp := GenerateResponse{ProofBase64: proofB64, ProverMS: elapsed}
	sendJSON(w, resp)
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	proofBytes, err := base64.StdEncoding.DecodeString(req.ProofBase64)
	if err != nil {
		http.Error(w, "invalid base64 proof: "+err.Error(), http.StatusBadRequest)
		return
	}

	var cptr *C.uint8_t
	var clen C.size_t = C.size_t(len(proofBytes))
	if len(proofBytes) > 0 {
		cptr = (*C.uint8_t)(C.CBytes(proofBytes))
		defer C.free(unsafe.Pointer(cptr))
	}

	start := time.Now()
	ok := C.zk_verify_proof(cptr, clen)
	elapsed := time.Since(start).Seconds() * 1000.0

	resp := VerifyResponse{Valid: bool(ok), VerifierMS: elapsed}
	sendJSON(w, resp)
}

func sendJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func main() {
	// simple HTTP JSON API:
	// POST /generate  body: { "a":..., "b":..., "const": ... }
	// POST /verify    body: { "proof_base64": "..." }

	http.HandleFunc("/generate", generateHandler)
	http.HandleFunc("/verify", verifyHandler)

	port := os.Getenv("ZK_RPC_PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	fmt.Printf("ZK RPC server listening on %s\n", addr)
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
	_ = server.Shutdown(context.Background())
}
