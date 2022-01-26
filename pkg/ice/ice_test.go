package ice_test

import (
	"testing"

	"github.com/markus-wa/ice-cipher-go/pkg/ice"
	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	k := ice.NewKey(1, []byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89})
	toEncrypt := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	encrypted := make([]byte, 8)

	k.Encrypt(toEncrypt, encrypted)

	expected := []byte{88, 76, 140, 254, 103, 42, 211, 107}
	assert.Equal(t, expected, encrypted)
}

func TestDecrypt(t *testing.T) {
	k := ice.NewKey(1, []byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89})
	toDecrypt := []byte{88, 76, 140, 254, 103, 42, 211, 107}

	decrypted := k.DecryptAll(toDecrypt)

	expected := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	assert.Equal(t, expected, decrypted)
}

func TestEncDec2(t *testing.T) {
	k := ice.NewKey(2, []byte{
		0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
		0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
	})
	toEncrypt := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	encrypted := make([]byte, 8)

	k.Encrypt(toEncrypt, encrypted)

	decrypted := k.DecryptAll(encrypted)

	assert.Equal(t, toEncrypt, decrypted)
}
