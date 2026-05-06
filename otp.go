// Package secureotp generates Time-based One-Time Passwords (TOTP).
//
// Each OTP is a no-repeat selection from the configured character set,
// produced by a HMAC-based byte stream feeding a Fisher-Yates shuffle.
// Every character in the output is drawn without replacement, so a length-6
// numeric OTP uses six distinct digits.
//
// Basic usage:
//
//	g, err := secureotp.New(secret)          // 6-digit numeric, 30 s, SHA-1
//	otp, err := g.GenerateNow()
//	ok, err  := g.Validate(otp, time.Now(), 1)
package secureotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"
)

const (
	charsetNumeric      = "0123456789"
	charsetAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

const (
	defaultLength = 6
	defaultPeriod = 30 * time.Second
)

// ── Public types ──────────────────────────────────────────────────────────────

// Complexity selects the pool of characters used when generating an OTP.
type Complexity int

const (
	// Numeric restricts output to digits 0–9 (pool size 10).
	Numeric Complexity = iota
	// Alphanumeric restricts output to uppercase letters A–Z and digits 0–9
	// (pool size 36).
	Alphanumeric
	// Custom uses the caller-supplied Charset (set via WithCharset).
	// The charset must be duplicate-free and at least as long as the OTP length.
	Custom
)

// HashAlgorithm selects the HMAC hash function used for both the time counter
// and the internal byte-stream generation.
type HashAlgorithm int

const (
	SHA1   HashAlgorithm = iota // HMAC-SHA-1
	SHA256                      // HMAC-SHA-256
	SHA512                      // HMAC-SHA-512
)

func (h HashAlgorithm) newFunc() func() hash.Hash {
	switch h {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// Option is a functional option that configures a Generator.
type Option func(*cfg)

// WithLength sets the number of characters in each generated OTP.
// Must be ≤ the size of the active character set. Default: 6.
func WithLength(n int) Option { return func(c *cfg) { c.length = n } }

// WithComplexity sets the character-set complexity. Default: Numeric.
func WithComplexity(comp Complexity) Option { return func(c *cfg) { c.complexity = comp } }

// WithCharset sets a custom, duplicate-free character set and implies Custom
// complexity. The charset must contain at least 2 characters and no character
// may appear more than once.
func WithCharset(charset string) Option {
	return func(c *cfg) {
		c.complexity = Custom
		c.charset = charset
	}
}

// WithPeriod sets the time-step duration. Default: 30s.
func WithPeriod(d time.Duration) Option { return func(c *cfg) { c.period = d } }

// WithHash sets the HMAC algorithm. Default: SHA1.
func WithHash(h HashAlgorithm) Option { return func(c *cfg) { c.hash = h } }

// WithT0 sets the Unix epoch reference time T0 (RFC 6238). Default: 0.
func WithT0(t0 int64) Option { return func(c *cfg) { c.t0 = t0 } }

// ── Generator ─────────────────────────────────────────────────────────────────

// Generator produces TOTP codes from a shared secret.
type Generator struct {
	c cfg
}

// New creates a Generator with the provided secret and zero or more options.
// Returns an error if the secret is empty or the configuration is invalid.
func New(secret []byte, opts ...Option) (*Generator, error) {
	if len(secret) == 0 {
		return nil, errors.New("secureotp: secret must not be empty")
	}
	c := cfg{
		secret:     secret,
		length:     defaultLength,
		complexity: Numeric,
		period:     defaultPeriod,
		hash:       SHA1,
		t0:         0,
	}
	for _, o := range opts {
		o(&c)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &Generator{c: c}, nil
}

// Generate produces a TOTP for the given instant t.
func (g *Generator) Generate(t time.Time) (string, error) {
	return g.fromCounter(g.counter(t))
}

// GenerateNow produces a TOTP for the current wall-clock time.
func (g *Generator) GenerateNow() (string, error) {
	return g.Generate(time.Now())
}

// Validate reports whether code is valid for any time step in the range
// [t − window·step, t + window·step]. Set window to 1 to absorb typical
// client/server clock drift.
//
// Comparison is performed in constant time (via hmac.Equal) to prevent
// timing-based side-channel attacks.
func (g *Generator) Validate(code string, t time.Time, window int) (bool, error) {
	if window < 0 {
		window = 0
	}
	center := g.counter(t)
	for delta := -int64(window); delta <= int64(window); delta++ {
		candidate, err := g.fromCounter(center + delta)
		if err != nil {
			return false, err
		}
		// hmac.Equal calls subtle.ConstantTimeCompare — safe against timing attacks.
		if hmac.Equal([]byte(candidate), []byte(code)) {
			return true, nil
		}
	}
	return false, nil
}

// ── Internal ──────────────────────────────────────────────────────────────────

type cfg struct {
	secret     []byte
	length     int
	complexity Complexity
	charset    string
	period     time.Duration
	hash       HashAlgorithm
	t0         int64
}

// effectiveCharset returns the character pool for the current configuration.
func (c *cfg) effectiveCharset() string {
	switch c.complexity {
	case Alphanumeric:
		return charsetAlphanumeric
	case Custom:
		return c.charset
	default:
		return charsetNumeric
	}
}

func (c *cfg) validate() error {
	if c.length <= 0 {
		return fmt.Errorf("secureotp: length must be positive, got %d", c.length)
	}
	if c.period <= 0 {
		return fmt.Errorf("secureotp: period must be positive, got %v", c.period)
	}
	if c.complexity == Custom {
		if len(c.charset) < 2 {
			return errors.New("secureotp: custom charset must have at least 2 characters")
		}
		if err := checkDuplicates(c.charset); err != nil {
			return err
		}
	}
	cs := c.effectiveCharset()
	if c.length > len(cs) {
		return fmt.Errorf(
			"secureotp: length %d exceeds charset size %d; "+
				"no-repeat OTPs require length ≤ charset size",
			c.length, len(cs),
		)
	}
	return nil
}

func checkDuplicates(s string) error {
	seen := make(map[byte]struct{}, len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if _, dup := seen[b]; dup {
			return fmt.Errorf("secureotp: custom charset contains duplicate character %q", b)
		}
		seen[b] = struct{}{}
	}
	return nil
}

// counter computes T = floor((unix(t) − T0) / step), clamped to 0.
func (g *Generator) counter(t time.Time) int64 {
	elapsed := t.Unix() - g.c.t0
	if elapsed < 0 {
		elapsed = 0
	}
	stepSec := int64(g.c.period) / int64(time.Second)
	return elapsed / stepSec
}

// fromCounter generates a no-repeat OTP for the given counter value.
//
// Algorithm:
//  1. Build a HMAC-based deterministic byte stream keyed on (secret, counter).
//  2. Run a Fisher-Yates partial shuffle over the charset using that stream
//     as the source of uniformly random indices.
//  3. Return the first `length` characters of the shuffled pool.
//
// This guarantees every character in the output comes from the charset and
// no character appears more than once, regardless of OTP length.
func (g *Generator) fromCounter(counter int64) (string, error) {
	stream := newCounterStream(g.c.hash.newFunc(), g.c.secret, counter)
	charset := g.c.effectiveCharset()
	n := g.c.length

	// pool is a mutable copy; Fisher-Yates swaps within it.
	pool := []byte(charset)
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		remaining := len(pool) - i
		j := i + stream.intn(remaining)
		pool[i], pool[j] = pool[j], pool[i]
		buf[i] = pool[i]
	}
	return string(buf), nil
}

// ── HMAC counter-mode byte stream ────────────────────────────────────────────

// counterStream produces a deterministic, pseudo-random byte stream by
// repeatedly computing HMAC(secret, counter ∥ blockNo) and consuming the
// digest bytes in order.
type counterStream struct {
	newFunc func() hash.Hash
	secret  []byte
	counter uint64
	blockNo uint64
	block   []byte
	pos     int
}

func newCounterStream(newFunc func() hash.Hash, secret []byte, counter int64) *counterStream {
	cs := &counterStream{
		newFunc: newFunc,
		secret:  secret,
		counter: uint64(counter),
	}
	cs.refill()
	return cs
}

func (cs *counterStream) refill() {
	var msg [16]byte
	binary.BigEndian.PutUint64(msg[:8], cs.counter)
	binary.BigEndian.PutUint64(msg[8:], cs.blockNo)
	cs.blockNo++
	mac := hmac.New(cs.newFunc, cs.secret)
	mac.Write(msg[:])
	cs.block = mac.Sum(nil)
	cs.pos = 0
}

func (cs *counterStream) readByte() byte {
	if cs.pos >= len(cs.block) {
		cs.refill()
	}
	b := cs.block[cs.pos]
	cs.pos++
	return b
}

// intn returns a uniformly distributed random integer in [0, n) using
// rejection sampling to eliminate modulo bias.
func (cs *counterStream) intn(n int) int {
	if n <= 1 {
		return 0
	}
	// Find the smallest number of bytes whose range covers [0, n).
	byteCount := 1
	var limit uint64 = 256
	for limit < uint64(n) {
		byteCount++
		limit <<= 8
	}
	// Discard values ≥ threshold to keep the distribution uniform.
	threshold := limit - (limit % uint64(n))
	for {
		var v uint64
		for i := 0; i < byteCount; i++ {
			v = (v << 8) | uint64(cs.readByte())
		}
		if v < threshold {
			return int(v % uint64(n))
		}
	}
}
