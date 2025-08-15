package main

import (
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"

	"libiop/go_zk/zk"
)

type ZKService struct {
	store *zk.Store
}

type GenerateArgs struct {
	A     uint64 `json:"a"`
	B     uint64 `json:"b"`
	Const uint64 `json:"const"`
}
type GenerateReply struct {
	ProofID string `json:"proof_id"`
}

func (s *ZKService) Generate(args *GenerateArgs, reply *GenerateReply) error {
	id, err := s.store.Generate(args.A, args.B, args.Const)
	if err != nil {
		return err
	}
	reply.ProofID = string(id)
	return nil
}

type VerifyArgs struct {
	ProofID string `json:"proof_id"`
}
type VerifyReply struct {
	OK bool `json:"ok"`
}

func (s *ZKService) Verify(args *VerifyArgs, reply *VerifyReply) error {
	ok, err := s.store.Verify(zk.ProofID(args.ProofID))
	if err != nil {
		return err
	}
	reply.OK = ok
	return nil
}

type FreeArgs struct {
	ProofID string `json:"proof_id"`
}
type FreeReply struct{}

func (s *ZKService) Free(args *FreeArgs, reply *FreeReply) error {
	return s.store.Free(zk.ProofID(args.ProofID))
}

func main() {
	store := zk.NewStore()
	defer store.Close()

	svc := &ZKService{store: store}
	if err := rpc.RegisterName("ZK", svc); err != nil {
		log.Fatalf("rpc.Register: %v", err)
	}

	addr := ":8547"
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("JSON-RPC listening on %s", addr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go jsonrpc.ServeConn(conn)
	}
}
