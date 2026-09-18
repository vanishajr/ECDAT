package main
import "crypto/ecdh"
func main(){ _, _ = ecdh.X25519().GenerateKey(nil) }
