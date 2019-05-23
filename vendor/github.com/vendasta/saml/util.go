package saml

import "crypto/rand"

const (
	letterBytes   = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ--"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)

func randomString(n int) string {
	random := make([]byte, n)
	// Generate a random array using crypto/rand
	_, err := rand.Read(random)
	if err != nil {
		panic(err.Error()) // rand should never fail
	}
	// Map the random array into an array of letters
	result := make([]byte, n)
	for i := range random {
		idx := int(random[i] & letterIdxMask)
		result[i] = letterBytes[idx]
	}

	return string(result)

}
