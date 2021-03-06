package main

import (
	"fmt"

	"github.com/markus-wa/ice-cipher-go/pkg/ice"
)

func main() {
	k := ice.NewKey(1, []byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89})
	toEncrypt := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	fmt.Println("to encrypt:", toEncrypt)

	// encrypt 8 bytes
	encrypted := make([]byte, 8)
	k.Encrypt(toEncrypt, encrypted)

	fmt.Println("encrypted:", encrypted)

	// decrypt 8 bytes
	decrypted := make([]byte, 8)
	k.Decrypt(encrypted, decrypted)

	fmt.Println("decrypted:", decrypted)

	// utility function to decrypt larger arrays
	decryptedTwice := k.DecryptAll(append(encrypted, encrypted...))

	fmt.Println("decrypted twice:", decryptedTwice)
}
