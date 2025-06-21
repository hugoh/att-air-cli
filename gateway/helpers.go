package gateway

// This is a Go translation of https://github.com/CptMeetKat/OptusDNSBypass/blob/f627f7cedb08086786315e8a40a74e63fa6338fb/RouterAPI/OptusHelpers.js

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

type D struct {
	h uint
	l uint
}

func E(e, t, i, n, a, r *D) {
	s := (t.l & 0xffff) + (i.l & 0xffff) + (n.l & 0xffff) + (a.l & 0xffff) + (r.l & 0xffff)
	O := (uint(t.l) >> 16) + (uint(i.l) >> 16) + (uint(n.l) >> 16) + (uint(a.l) >> 16) + (uint(r.l) >> 16) + (uint(s) >> 16)
	o := (t.h & 0xffff) + (i.h & 0xffff) + (n.h & 0xffff) + (a.h & 0xffff) + (r.h & 0xffff) + uint(O)>>16
	l := (uint(t.h) >> 16) + (uint(i.h) >> 16) + (uint(n.h) >> 16) + (uint(a.h) >> 16) + (uint(r.h) >> 16) + (uint(o) >> 16)
	e.l = s&0xffff | uint(O)<<16
	e.h = o&0xffff | uint(l)<<16
}

func calculateSaltedPassword(salt, password string) string {
	hashed, err := unknownHash(password, salt)
	if err != nil {
		return ""
	}
	return hashed
}

func lpad(num float64, pad string, length int) string {
	s := fmt.Sprintf("%.0f", num)
	if len(s) >= length {
		return s
	}
	return strings.Repeat(pad, length-len(s)) + s
}

func generateCNonce() string {
	const RESTGUI_LOGIN_MAX_CNONCE float64 = 10000000000000000000
	// Generate a random number up to RESTGUI_LOGIN_MAX_CNONCE using crypto/rand
	maxBig := big.NewFloat(RESTGUI_LOGIN_MAX_CNONCE)
	maxInt := new(big.Int)
	maxBig.Int(maxInt)

	randBig, err := rand.Int(rand.Reader, maxInt)
	if err != nil {
		return lpad(0, "0", 19) // Fallback to padded zero on error
	}

	randFloat, _ := new(big.Float).SetInt(randBig).Float64()

	return lpad(randFloat, "0", 19)
}

var b64Chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func customBase64Encode(input string, order []int) string {
	var output strings.Builder
	for i := 0; i < len(order); i += 3 {
		if i+2 >= len(order) {
			// handle 1–2 leftover bytes
			b0 := input[order[i]]
			var b1 byte = 0
			if i+1 < len(order) {
				b1 = input[order[i+1]]
			}
			output.WriteByte(b64Chars[b0&0x3f])
			output.WriteByte(b64Chars[(b0>>6)|(b1<<2)&0x3f])
		} else {
			b0 := input[order[i]]
			b1 := input[order[i+1]]
			b2 := input[order[i+2]]

			r := b0 & 0x3f
			s := ((b0 >> 6) | ((b1 & 0x0f) << 2)) & 0x3f
			o := ((b1 >> 4) | ((b2 & 0x03) << 4)) & 0x3f
			p := (b2 >> 2) & 0x3f

			output.WriteByte(b64Chars[r])
			output.WriteByte(b64Chars[s])
			output.WriteByte(b64Chars[o])
			output.WriteByte(b64Chars[p])
		}
	}
	return output.String()
}

func T(s string) string {
	sum := sha512.Sum512([]byte(s))
	return string(sum[:])
}

func g(input string, length int) string {
	var result strings.Builder
	for len(result.String()) < length {
		result.WriteString(input)
	}
	return result.String()[:length]
}

func pbkdfLike(password, salt string, rounds int) string {
	// Step 1
	n := func() string {
		h := T(password + salt + password)
		r := password + salt + g(h, len(password))
		for a := len(password); a > 0; a >>= 1 {
			if a&1 != 0 {
				r += h
			} else {
				r += password
			}
		}
		return T(r)
	}()

	s := g(T(strings.Repeat(password, len(password))), len(password))
	o := g(T(strings.Repeat(salt, 16+int(n[0]))), len(salt))

	c := n
	for i := range rounds {
		var d strings.Builder
		if i&1 != 0 {
			d.WriteString(s)
		} else {
			d.WriteString(c)
		}
		if i%3 != 0 {
			d.WriteString(o)
		}
		if i%7 != 0 {
			d.WriteString(s)
		}
		if i&1 != 0 {
			d.WriteString(c)
		} else {
			d.WriteString(s)
		}
		c = T(d.String())
	}
	return c
}

func unknownHash(e, t string) (string, error) {
	parts := strings.Split(t, "$")
	if len(parts) == 1 {
		parts = append([]string{"", "6"}, parts...)
		// 	return "", errors.New("invalid salt format")
	}
	if parts[1] != "6" {
		return "", fmt.Errorf("got '%s' but only SHA512 ($6$) algorithm supported", parts[1])
	}

	var rounds int
	var salt string
	roundsSpecified := true

	if len(parts) > 2 && strings.HasPrefix(parts[2], "rounds=") {
		r, err := strconv.Atoi(strings.Split(parts[2], "=")[1])
		if err != nil {
			return "", err
		}
		if r < 1000 {
			r = 1000
		}
		if r > 999999999 {
			r = 999999999
		}
		rounds = r
		if len(parts) > 3 {
			salt = parts[3]
		}
	} else {
		salt = parts[2]
		rounds = 5000
		roundsSpecified = false
	}

	if len(salt) < 8 || len(salt) > 16 {
		return "", fmt.Errorf("wrong salt length: '%d' bytes when 8 <= n <= 16 expected. Got salt '%s'", len(salt), salt)
	}

	hash := pbkdfLike(e, salt, rounds)
	order := []int{
		42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47,
		48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52, 31, 32, 11, 53,
		54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15, 16, 58, 37, 38, 17,
		59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
	}
	encoded := customBase64Encode(hash, order)

	prefix := "$6$"
	if roundsSpecified {
		prefix = fmt.Sprintf("$6$rounds=%d$", rounds)
	}
	result := prefix + salt + "$" + encoded
	return result, nil
}
