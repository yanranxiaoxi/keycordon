package rewrite

import (
	"encoding/pem"
	"strings"
)

// testPEM builds a real PEM private key of a chosen body length, so a test
// can place a secret that is longer than the chunk overlap. It is generated at
// run time: no key material lives in the repository.
func testPEM(lines int) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte(strings.Repeat("k", lines*48)),
	}))
}
