package main

import (
	"fmt"
	"log"
	"time"

	"github.com/jwc65535/secureotp"
)

func main() {
	secret := []byte("supersecretkey42")

	fmt.Println("=== secureotp demonstration ===")
	fmt.Println()

	// 1. Default: 6-digit numeric, 30 s, SHA-1.
	g, err := secureotp.New(secret)
	if err != nil {
		log.Fatal(err)
	}
	otp, err := g.GenerateNow()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Default (6-digit, 30 s, SHA-1):       %s\n", otp)

	// 2. 8-digit numeric, 60-second window.
	g60, err := secureotp.New(secret,
		secureotp.WithLength(8),
		secureotp.WithPeriod(60*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}
	otp60, _ := g60.GenerateNow()
	fmt.Printf("8-digit, 60 s window:                  %s\n", otp60)

	// 3. Alphanumeric, 6 characters, SHA-256.
	gAlpha, err := secureotp.New(secret,
		secureotp.WithLength(6),
		secureotp.WithComplexity(secureotp.Alphanumeric),
		secureotp.WithHash(secureotp.SHA256),
	)
	if err != nil {
		log.Fatal(err)
	}
	otpAlpha, _ := gAlpha.GenerateNow()
	fmt.Printf("Alphanumeric (A-Z0-9), SHA-256:        %s\n", otpAlpha)

	// 4. Custom charset — hex digits only.
	gHex, err := secureotp.New(secret,
		secureotp.WithLength(16),
		secureotp.WithCharset("0123456789ABCDEF"),
	)
	if err != nil {
		log.Fatal(err)
	}
	otpHex, _ := gHex.GenerateNow()
	fmt.Printf("Custom charset (hex digits):           %s\n", otpHex)

	// 5. Demonstrate Validate with a ±1-step window.
	fmt.Println()
	fmt.Println("=== Validate ===")
	now := time.Now()
	current, _ := g.Generate(now)
	fmt.Printf("Generated OTP:  %s\n", current)

	ok, _ := g.Validate(current, now, 1)
	fmt.Printf("Validate (correct, window=1): %v\n", ok)

	ok, _ = g.Validate("000000", now, 1)
	fmt.Printf("Validate (wrong,   window=1): %v\n", ok)

	// 6. Show that the OTP is stable across the full 30-second window.
	fmt.Println()
	fmt.Println("=== Time-step stability ===")
	stepStart := (now.Unix() / 30) * 30
	t0 := time.Unix(stepStart, 0)
	t1 := time.Unix(stepStart+15, 0)
	t2 := time.Unix(stepStart+29, 0)
	a, _ := g.Generate(t0)
	b, _ := g.Generate(t1)
	c, _ := g.Generate(t2)
	fmt.Printf("At step+0s:  %s\n", a)
	fmt.Printf("At step+15s: %s\n", b)
	fmt.Printf("At step+29s: %s\n", c)
	fmt.Printf("All equal:   %v\n", a == b && b == c)
}
