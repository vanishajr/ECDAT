package main
import (
 "crypto/ed25519"
 "crypto/rand"
)
func main(){ _,_,_ = ed25519.GenerateKey(rand.Reader) }
