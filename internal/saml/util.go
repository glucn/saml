package saml

import "crypto/rand"

const (
	letterBytes   = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)

func randomString(n int) string {
	random := make([]byte, n)
	result := make([]byte, n)

	_, err := rand.Read(random)
	if err != nil {
		panic(err.Error()) // rand should never fail
	}
	for i, r := range random {
		idx := int(r & letterIdxMask)
		result[i] = letterBytes[idx]
	}

	return string(result)

}
