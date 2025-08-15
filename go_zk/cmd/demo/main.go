package main

import (
	"fmt"
	"log"

	"libiop/go_zk/zk"
)

func main() {
	// Example inputs
	zk.SetInputs(232312, 13131, 1424124)

	proof, err := zk.GenerateProof()
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}
	fmt.Printf("Proof generated (%d bytes)\n", len(proof))

	// Now verify
	ok := zk.VerifyProof(proof)
	fmt.Println("Verification result:", ok)
}
