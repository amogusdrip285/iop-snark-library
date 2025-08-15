package zk

/*
#cgo CFLAGS: -I../../ffi -I../../ffi_cgo
#cgo LDFLAGS: -L../../build -lzkffi_wrapper
#include <stdint.h>
#include <stdbool.h>

// Keep these prototypes in sync with ffi/libiop_ffi.h
typedef struct proof_handle_t proof_handle_t;

extern void set_r1cs_input_values(uint64_t a, uint64_t b, uint64_t const_val);
extern proof_handle_t* generate_r1cs_proof_obj();
extern bool verify_r1cs_proof_obj(proof_handle_t* h);
extern void free_proof_obj(proof_handle_t* h);
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

type ProofID string

type Store struct {
	mu     sync.Mutex
	next   uint64
	proofs map[ProofID]*C.proof_handle_t
}

func NewStore() *Store {
	return &Store{
		proofs: make(map[ProofID]*C.proof_handle_t),
	}
}

func (s *Store) Generate(a, b, k uint64) (ProofID, error) {
	// set inputs for this run
	C.set_r1cs_input_values(C.uint64_t(a), C.uint64_t(b), C.uint64_t(k))
	h := C.generate_r1cs_proof_obj()
	if h == nil {
		return "", errors.New("generate_r1cs_proof_obj returned NULL")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := ProofID(fmt.Sprintf("p-%d", s.next))
	s.proofs[id] = h
	return id, nil
}

func (s *Store) Verify(id ProofID) (bool, error) {
	s.mu.Lock()
	h := s.proofs[id]
	s.mu.Unlock()
	if h == nil {
		return false, errors.New("unknown proof id")
	}
	ok := bool(C.verify_r1cs_proof_obj(h))
	return ok, nil
}

func (s *Store) Free(id ProofID) error {
	s.mu.Lock()
	h := s.proofs[id]
	if h != nil {
		delete(s.proofs, id)
	}
	s.mu.Unlock()
	if h == nil {
		return errors.New("unknown proof id")
	}
	C.free_proof_obj(h)
	return nil
}

// Cleanup everything (optional)
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, h := range s.proofs {
		if h != nil {
			C.free_proof_obj(h)
		}
		delete(s.proofs, id)
	}
}

// only to prevent "unsafe" import being unused if you remove it later
var _ = unsafe.Pointer(nil)
