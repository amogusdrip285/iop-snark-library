// go_zk/rpc/service.go
package rpc

import "libiop/go_zk/zk"

type JobRequest struct {
	A        uint64 `json:"a"`
	B        uint64 `json:"b"`
	ConstVal uint64 `json:"const_val"`
}

type ProofResponse struct {
	Proof    []byte  `json:"proof"`
	ProverMS float64 `json:"prover_ms"`
	Error    string  `json:"error,omitempty"`
}

type VerifyRequest struct {
	Proof []byte `json:"proof"`
}

type VerifyResponse struct {
	Verified   bool    `json:"verified"`
	VerifierMS float64 `json:"verifier_ms"`
}

type ZkService struct{}

func (s *ZkService) SubmitJob(req JobRequest, resp *ProofResponse) error {
	zk.SetInputs(req.A, req.B, req.ConstVal)
	proof, ms, ok := zk.GenerateProof()
	if !ok {
		resp.Error = "failed to generate proof"
		return nil
	}
	resp.Proof = proof
	resp.ProverMS = ms
	return nil
}

func (s *ZkService) VerifyJob(req VerifyRequest, resp *VerifyResponse) error {
	ok, ms := zk.VerifyProof(req.Proof)
	resp.Verified = ok
	resp.VerifierMS = ms
	return nil
}
