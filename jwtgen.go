// A simple app for generating JWT tokens for local testing

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Globals
var (
	// CLI Flags
	flagISS         = flag.String("iss", "https://appleid.apple.com", "Issuer for token")
	flagAUD         = flag.String("aud", "com.fake.fake.AppleSignIn", "Audience for token")
	flagEXP         = flag.Bool("expired", false, "Should the token be expired, defaults to false")
	flagSubject     = flag.String("sub", "Test User", "Subject of the token")
	flagEmail       = flag.String("email", "test@example.com", "Email of user")
	flagError       = flag.String("error", "", "Specfiy an error message in this token")
	flagPrettyPrint = flag.Bool("pp", false, "Pretty print JSON, defaults to false.")
	flagDebug       = flag.Bool("debug", false, "Print some debug information")
)

const (
	// Our public and private key, just randomly generated with:
	// openssl genrsa -out private.pem 2048
	// openssl rsa -in private.pem -pubout > public.pem
	pubKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPT/9wrDF7qn2RH81cQsMdt+G+
GSlkFQy+mxBO2DiIaX64R/lSj5gcEMRdWRbSQLvVUW6ws5SAM2Gr3YwaoADZJ3Bo
HF3BzTi2wiMOwSgLJtw3etmJkSMM6ewsI6I0wYqGVlqgvsva/qlCrtXHpjAz/5qg
aeBfg2OV5e7sIeOnVwIDAQAB
-----END PUBLIC KEY-----`
	privKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDPT/9wrDF7qn2RH81cQsMdt+G+GSlkFQy+mxBO2DiIaX64R/lS
j5gcEMRdWRbSQLvVUW6ws5SAM2Gr3YwaoADZJ3BoHF3BzTi2wiMOwSgLJtw3etmJ
kSMM6ewsI6I0wYqGVlqgvsva/qlCrtXHpjAz/5qgaeBfg2OV5e7sIeOnVwIDAQAB
AoGAQYY9bHVgZn/qlDYDCIgpd3kpJpZ5WKK2loAYVXNN2v/NB53oFcpA/43lIsQH
zIidVb0ZSUxZQXP8CQBLShcMbQS7ZIWw3fDesmk8rWTe57nMAwhXJAPrkW0Gzgh0
fpccQGIRfLmRUmOC1WKK7bS8t3UwOEzzbmLlCtENHd0QEIECQQDrJWEMRaoDpZ7G
lSh1dGeScVTtsMnMew716mSZK5A3zOMfyyPcbL+hzeadV+RojEeu9cdrx1AYMC4h
C9xRrq83AkEA4bKzzPf9RMiqYrybp3lySMKfRArcc8K+mDpLpAok82Xleh2BWFkT
iqsM59a4NiuexvI+pDpjQbtUte8DhsWY4QJAdEEhruCOQolSa1l5DEDFp/gSBgWe
b1LzvY7pt3R7M6s/KwvSqfq173gNqQK4MRwRoKVwt49twNepJrtnbJbRlwJADlHG
MpTxTrHkjYsl3QRJifA/JpQB1J5gdUwNjITQP1kRrCO/FxnfsYaUtQjceyNdWYX5
D3Zc4ci+4SQe9ygGQQJAe25VWm6kUd2LQQa34lsGIlN344C0DRZmeW2DBD2DUN1S
wr6fQ4vk0r5W1JxGVyMhZCfbzulXFn04G1N2n54aFA==
-----END RSA PRIVATE KEY-----`
)

// This struct holds the same structure as a JWT payload from Apple
type payload struct {
	Email          string `json:"email"`
	Error          string `json:"err,omitempty"`
	EmailVerified  string `json:"email_verified"`
	NonceSupported bool   `json:"nonce_supported"`
	jwt.RegisteredClaims
}

func main() {
	// Create a usage message that contains examples instead of just default args.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example usages:\n")
		fmt.Fprintf(os.Stderr, "  Generate a default, valid token:\n")
		fmt.Fprintf(os.Stderr, "    jwtgen\n")
		fmt.Fprintf(os.Stderr, "  Generate a default, valid token, and pretty-print debug information:\n")
		fmt.Fprintf(os.Stderr, "    jwtgen --debug -pp\n")
		fmt.Fprintf(os.Stderr, "  Generate an expired token for cole@test.com:\n")
		fmt.Fprintf(os.Stderr, "    jwtgen --expired --email=cole@test.com\n")
		fmt.Fprintf(os.Stderr, "\nOptions: \n")

		flag.PrintDefaults()
	}

	// First things first, parse our CLI flags.
	flag.Parse()

	// Generate a token out of all of our claims, optionally print them.
	claims, err := generateToken()

	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}

	// Sign and print!
	if err := signToken(claims); err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}

func printJSON(j interface{}) error {
	var parsedJSON []byte
	var err error
	if *flagPrettyPrint {
		parsedJSON, err = json.MarshalIndent(j, "", "    ")
	} else {
		parsedJSON, err = json.Marshal(j)
	}

	if err == nil {
		fmt.Println(string(parsedJSON))
	}

	return err
}

func generateToken() (payload, error) {
	// Generate an expiration based on whether or not this token should
	// be expired.
	var expiration int64
	if *flagEXP {
		expiration = time.Now().UTC().Unix() - 100000000 // Back two years
	} else {
		expiration = time.Now().UTC().Unix() + 100000000 // Plus two years
	}

	var errorValue string
	if *flagError != "" {
		validErrors := []string{"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope"}
		for _, errorString := range validErrors {
			if *flagError == errorString {
				errorValue = *flagError
			}
		}

		if errorValue == "" {
			return payload{}, fmt.Errorf("Provided error value \"%s\" not valid", *flagError)
		}
	}

	return payload{
		*flagEmail, // Email
		errorValue, // Error message (optional)
		"true",     // EmailVerified -- Apple sends this as a string instead of a bool
		true,       // NonceSupported -- Alaways true as a bool
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(expiration, 0)),
			Issuer:    *flagISS,
			Audience:  []string{*flagAUD},
			Subject:   *flagSubject,
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
	}, nil
}

func signToken(claims payload) error {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Just need something here so it looks like it came from Apple.
	token.Header["kid"] = "86D88Kf"

	var err error
	if *flagDebug {
		printJSON(token.Header)
		printJSON(token.Claims)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKey))
	if err != nil {
		return fmt.Errorf("Error loading private key: %v", err)
	}

	if signedKey, err := token.SignedString(key); err == nil {
		fmt.Println(signedKey)
	} else {
		return fmt.Errorf("Error signing token: %v", err)
	}

	return nil
}
