# ice-cipher-go

An implementation of the [Information Concealment Engine](https://en.wikipedia.org/wiki/ICE_(cipher)) cipher in Go.

Takes a 64 bit (8 byte) key, 64 bits of data and returns the encrypted/decrypted 64 bit result.

_Ice Ice Baby_

<img src="https://user-images.githubusercontent.com/5138316/151227751-f2772f85-c311-41b8-99b4-6cc73379902c.png" alt="ice ice baby" width="300"/>

### Go Get

    go get github.com/markus-wa/ice-cipher-go/pkg/ice
    
### Usage

example from `example/main.go`

```
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
```

run via `go run example/main.go`

prints

```
to encrypt: [17 34 51 68 85 102 119 136]
encrypted: [88 76 140 254 103 42 211 107]
decrypted: [17 34 51 68 85 102 119 136]
decrypted twice: [17 34 51 68 85 102 119 136 17 34 51 68 85 102 119 136]
```
