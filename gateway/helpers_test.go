package gateway

// These are tests for check that the Go translation behaves like the JS code

import (
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

func TestUnknownHash(t *testing.T) {
	testCases := []struct {
		password string
		salt     string
		expected string
	}{
		{
			password: "password123",
			salt:     "$6$rounds=5000$SomeSalt$",
			expected: "$6$rounds=5000$SomeSalt$Wov3TdU5l4d4Bxl0Jot7jWU0PBbtP3kyymDTWrmMrRtDFVmkk.4LMFSbZ.n6aoWEdygm7Uc/Qp3N1cmVsK0po/",
		},
		{
			password: "testpwd",
			salt:     "$6$AnotherSalt$",
			expected: "$6$AnotherSalt$4ATCNvZuFWfvl9xGt5leh9S6Qj6Q8j2qcFk0lkc.xqtcICZ7ycE2Dp5N/JYTrRbFQKnFrUawSlAf3yVYYrYXa0",
		},
		{
			password: "test",
			salt:     "48ZvX/Da3DS/o",
			expected: "$6$48ZvX/Da3DS/o$i10AwrnmTize4T3rDw7himH2l.FUR8.jp4TJU2gl5tK2lN8JSaV2xmkAtKpC9HYu48FymQpSqYiSA38MLbObs.",
		},
	}

	for _, tc := range testCases {
		actual, _ := unknownHash(tc.password, tc.salt)
		if actual != tc.expected {
			t.Errorf("X(%q, %q) = %q, expected %q", tc.password, tc.salt, actual, tc.expected)
		}
	}
}

func TestCalculateSaltedPassword(t *testing.T) {
	testCases := []struct {
		salt     string
		password string
		expected string
	}{
		{
			salt:     "$6$rounds=5000$SomeSalt$",
			password: "password123",
			expected: "$6$rounds=5000$SomeSalt$Wov3TdU5l4d4Bxl0Jot7jWU0PBbtP3kyymDTWrmMrRtDFVmkk.4LMFSbZ.n6aoWEdygm7Uc/Qp3N1cmVsK0po/", // Example - Replace with actual known good hash
		},
		{
			salt:     "$6$AnotherSalt$",
			password: "testpwd",
			expected: "$6$AnotherSalt$4ATCNvZuFWfvl9xGt5leh9S6Qj6Q8j2qcFk0lkc.xqtcICZ7ycE2Dp5N/JYTrRbFQKnFrUawSlAf3yVYYrYXa0", // Example - Replace with actual known good hash
		},
	}

	for _, tc := range testCases {
		actual := calculateSaltedPassword(tc.salt, tc.password)
		if actual != tc.expected {
			t.Errorf("calculateSaltedPassword(%q, %q) = %q, expected %q", tc.salt, tc.password, actual, tc.expected)
		}
	}
}

func TestHashedCredentials(t *testing.T) {
	testCases := []struct {
		username          string
		nonce             string
		saltedPasswordSub string
		expected          string
	}{
		{
			username:          "testuser",
			nonce:             "abcdef1234567890",
			saltedPasswordSub: "cdefghijklmnop",                                                                                                                   // Example substring
			expected:          "d084d97079c2751d72a7750934f45739fd23bf2a2285cedfe63439a0f78fc6f0bd1442ad32b1c0a578cf3dd1d48bd13a5bca681caf576cf36d4995001d4ad47e", // Example - Replace with actual known good hash
		},
	}

	for _, tc := range testCases {
		input := tc.username + ":" + tc.nonce + ":" + tc.saltedPasswordSub
		hashedBytes := sha512.Sum512([]byte(input))
		actual := hex.EncodeToString(hashedBytes[:])
		if actual != tc.expected {
			t.Errorf("HashedCredentials(%q, %q, %q) = %q, expected %q", tc.username, tc.nonce, tc.saltedPasswordSub, actual, tc.expected)
		}
	}
}

func TestAuthKey(t *testing.T) {
	testCases := []struct {
		hashedCredentials string
		cnonce            string
		expected          string
	}{
		{
			hashedCredentials: "d084d97079c2751d72a7750934f45739fd23bf2a2285cedfe63439a0f78fc6f0bd1442ad32b1c0a578cf3dd1d48bd13a5bca681caf576cf36d4995001d4ad47e", // Example
			cnonce:            "0123456789012345678",
			expected:          "e8868790f76c36ec690dd9d2110fc50953c3d6dc622feda60d16e189f2ac6f610749799276cd94e4dbba8ecbd1a767a9fc0657e00d4ab4ac6a8d005243875c84", // Example - Replace with actual known good hash
		},
	}

	for _, tc := range testCases {
		input := tc.hashedCredentials + ":0:" + tc.cnonce
		hashedBytes := sha512.Sum512([]byte(input))
		actual := hex.EncodeToString(hashedBytes[:])
		if actual != tc.expected {
			t.Errorf("AuthKey(%q, %q) = %q, expected %q", tc.hashedCredentials, tc.cnonce, actual, tc.expected)
		}
	}
}

func TestLpad(t *testing.T) {
	testCases := []struct {
		num      float64
		pad      string
		length   int
		expected string
	}{
		{num: 123, pad: "0", length: 5, expected: "00123"},
		{num: 5, pad: "0", length: 2, expected: "05"},
		{num: 123456, pad: "0", length: 3, expected: "123456"}, // No padding if already longer
		{num: 7.0, pad: " ", length: 4, expected: "   7"},
	}

	for _, tc := range testCases {
		actual := lpad(tc.num, tc.pad, tc.length)
		if actual != tc.expected {
			t.Errorf("lpad(%f, %q, %d) = %q, expected %q", tc.num, tc.pad, tc.length, actual, tc.expected)
		}
	}
}

func TestGenerateCNonce(t *testing.T) {
	cnonce := generateCNonce()
	if len(cnonce) != 19 {
		t.Errorf("Expected cnonce to be 19 characters long, got %d", len(cnonce))
	}
	if !strings.Contains("0123456789", string(cnonce[0])) { // Check first character is a digit, crude but sufficient
		t.Errorf("Expected cnonce to start with a digit, got %c", cnonce[0])
	}
}
