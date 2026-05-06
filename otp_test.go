package secureotp_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jwc65535/secureotp"
)

// shared secret used throughout
var secret = []byte("12345678901234567890")

// ── Pinned output regression tests ───────────────────────────────────────────
//
// These lock the Fisher-Yates / HMAC-stream algorithm to known outputs.
// They must be updated deliberately if the algorithm changes.
// Every value has been verified to contain no repeated characters.

type pinnedVector struct {
	name    string
	unixSec int64
	hashAlg secureotp.HashAlgorithm
	want    string
}

var pinnedVectors = []pinnedVector{
	{"SHA1/59", 59, secureotp.SHA1, "41263709"},
	{"SHA1/1111111109", 1111111109, secureotp.SHA1, "60428371"},
	{"SHA1/1111111111", 1111111111, secureotp.SHA1, "53618270"},
	{"SHA1/1234567890", 1234567890, secureotp.SHA1, "17964832"},
	{"SHA1/2000000000", 2000000000, secureotp.SHA1, "12504937"},
	{"SHA1/20000000000", 20000000000, secureotp.SHA1, "56093748"},

	{"SHA256/59", 59, secureotp.SHA256, "42630981"},
	{"SHA256/1111111109", 1111111109, secureotp.SHA256, "93860214"},
	{"SHA256/1111111111", 1111111111, secureotp.SHA256, "16028359"},
	{"SHA256/1234567890", 1234567890, secureotp.SHA256, "17368240"},
	{"SHA256/2000000000", 2000000000, secureotp.SHA256, "65914802"},
	{"SHA256/20000000000", 20000000000, secureotp.SHA256, "25906873"},

	{"SHA512/59", 59, secureotp.SHA512, "35940278"},
	{"SHA512/1111111109", 1111111109, secureotp.SHA512, "23954781"},
	// "06829471" verifies leading-zero preservation.
	{"SHA512/1111111111", 1111111111, secureotp.SHA512, "06829471"},
	{"SHA512/1234567890", 1234567890, secureotp.SHA512, "95683174"},
	{"SHA512/2000000000", 2000000000, secureotp.SHA512, "74529638"},
	{"SHA512/20000000000", 20000000000, secureotp.SHA512, "10925387"},
}

func TestPinnedOutputs(t *testing.T) {
	for _, tc := range pinnedVectors {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			g, err := secureotp.New(secret,
				secureotp.WithLength(8),
				secureotp.WithHash(tc.hashAlg),
			)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got, err := g.Generate(time.Unix(tc.unixSec, 0))
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ── No-repeat property ────────────────────────────────────────────────────────

// assertNoRepeat fails the test if any byte appears more than once in s.
func assertNoRepeat(t *testing.T, otp, label string) {
	t.Helper()
	seen := make(map[byte]bool, len(otp))
	for i := 0; i < len(otp); i++ {
		b := otp[i]
		if seen[b] {
			t.Errorf("%s: character %q repeats in OTP %q", label, b, otp)
		}
		seen[b] = true
	}
}

func TestNoRepeat_Numeric(t *testing.T) {
	g, err := secureotp.New(secret, secureotp.WithLength(8))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, ts := range []int64{59, 1111111109, 1234567890, 2000000000} {
		otp, _ := g.Generate(time.Unix(ts, 0))
		assertNoRepeat(t, otp, "numeric/T="+fmt.Sprint(ts))
	}
}

func TestNoRepeat_Alphanumeric(t *testing.T) {
	g, err := secureotp.New(secret,
		secureotp.WithLength(12),
		secureotp.WithComplexity(secureotp.Alphanumeric),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, _ := g.Generate(time.Unix(1234567890, 0))
	assertNoRepeat(t, otp, "alphanumeric")
}

func TestNoRepeat_Custom(t *testing.T) {
	const charset = "ABCDEFGHIJ"
	g, err := secureotp.New(secret,
		secureotp.WithLength(6),
		secureotp.WithCharset(charset),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, _ := g.Generate(time.Unix(1234567890, 0))
	assertNoRepeat(t, otp, "custom")
}

func TestNoRepeat_FullPermutation(t *testing.T) {
	// length == charset size → OTP is a complete permutation.
	g, err := secureotp.New(secret, secureotp.WithLength(10))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, _ := g.Generate(time.Unix(59, 0))
	if len(otp) != 10 {
		t.Fatalf("expected length 10, got %d", len(otp))
	}
	assertNoRepeat(t, otp, "full-permutation")
	// Every digit 0-9 must appear exactly once.
	for c := byte('0'); c <= '9'; c++ {
		if !strings.Contains(otp, string(c)) {
			t.Errorf("digit %q missing from full permutation %q", c, otp)
		}
	}
}

// ── Constructor / config validation ──────────────────────────────────────────

func TestNew_EmptySecret(t *testing.T) {
	if _, err := secureotp.New(nil); err == nil {
		t.Fatal("expected error for nil secret")
	}
	if _, err := secureotp.New([]byte{}); err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestNew_ZeroLength(t *testing.T) {
	if _, err := secureotp.New(secret, secureotp.WithLength(0)); err == nil {
		t.Fatal("expected error for length=0")
	}
}

func TestNew_NegativeLength(t *testing.T) {
	if _, err := secureotp.New(secret, secureotp.WithLength(-3)); err == nil {
		t.Fatal("expected error for negative length")
	}
}

func TestNew_ZeroPeriod(t *testing.T) {
	if _, err := secureotp.New(secret, secureotp.WithPeriod(0)); err == nil {
		t.Fatal("expected error for zero period")
	}
}

func TestNew_NegativePeriod(t *testing.T) {
	if _, err := secureotp.New(secret, secureotp.WithPeriod(-30*time.Second)); err == nil {
		t.Fatal("expected error for negative period")
	}
}

func TestNew_CustomCharsetTooShort(t *testing.T) {
	for _, cs := range []string{"", "x"} {
		if _, err := secureotp.New(secret, secureotp.WithCharset(cs)); err == nil {
			t.Errorf("expected error for charset %q", cs)
		}
	}
}

func TestNew_DuplicateCharset(t *testing.T) {
	if _, err := secureotp.New(secret, secureotp.WithCharset("AABCD")); err == nil {
		t.Fatal("expected error for charset with duplicate characters")
	}
}

func TestNew_LengthExceedsCharset(t *testing.T) {
	// Numeric pool = 10; requesting 11 must fail.
	if _, err := secureotp.New(secret, secureotp.WithLength(11)); err == nil {
		t.Fatal("expected error: length 11 > numeric charset size 10")
	}
	// Alphanumeric pool = 36; requesting 37 must fail.
	if _, err := secureotp.New(secret,
		secureotp.WithLength(37),
		secureotp.WithComplexity(secureotp.Alphanumeric),
	); err == nil {
		t.Fatal("expected error: length 37 > alphanumeric charset size 36")
	}
	// Custom pool of 4; requesting 5 must fail.
	if _, err := secureotp.New(secret,
		secureotp.WithLength(5),
		secureotp.WithCharset("ABCD"),
	); err == nil {
		t.Fatal("expected error: length 5 > custom charset size 4")
	}
}

func TestNew_LengthEqualsCharset(t *testing.T) {
	// length == charset size is the boundary: must succeed.
	if _, err := secureotp.New(secret, secureotp.WithLength(10)); err != nil {
		t.Fatalf("length == charset size must be valid: %v", err)
	}
}

func TestNew_ValidDefaults(t *testing.T) {
	g, err := secureotp.New(secret)
	if err != nil {
		t.Fatalf("New with defaults: %v", err)
	}
	otp, err := g.Generate(time.Unix(1234567890, 0))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(otp) != 6 {
		t.Errorf("default length: got %d, want 6", len(otp))
	}
	for _, ch := range otp {
		if ch < '0' || ch > '9' {
			t.Errorf("non-numeric character %q in default OTP %q", ch, otp)
		}
	}
	assertNoRepeat(t, otp, "defaults")
}

// ── Length variants ───────────────────────────────────────────────────────────

func TestLength(t *testing.T) {
	for _, n := range []int{4, 6, 8, 10} {
		g, err := secureotp.New(secret, secureotp.WithLength(n))
		if err != nil {
			t.Fatalf("New(length=%d): %v", n, err)
		}
		otp, err := g.Generate(time.Unix(59, 0))
		if err != nil {
			t.Fatalf("Generate(length=%d): %v", n, err)
		}
		if len(otp) != n {
			t.Errorf("length=%d: got OTP length %d (%q)", n, len(otp), otp)
		}
		assertNoRepeat(t, otp, fmt.Sprintf("length=%d", n))
	}
}

// ── Period / duration variants ────────────────────────────────────────────────

func TestPeriod_60s(t *testing.T) {
	g, err := secureotp.New(secret, secureotp.WithPeriod(60*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	base := int64(1234567800) // divisible by 60
	otp1, _ := g.Generate(time.Unix(base, 0))
	otp2, _ := g.Generate(time.Unix(base+59, 0))
	if otp1 != otp2 {
		t.Errorf("same 60s window: %q != %q", otp1, otp2)
	}
}

func TestPeriod_WindowBoundary(t *testing.T) {
	g, err := secureotp.New(secret, secureotp.WithPeriod(30*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp1, _ := g.Generate(time.Unix(1111111109, 0)) // counter 37037036
	otp2, _ := g.Generate(time.Unix(1111111111, 0)) // counter 37037037
	if otp1 == otp2 {
		t.Error("adjacent 30s windows must produce different OTPs")
	}
}

// ── Complexity / character set ────────────────────────────────────────────────

func TestComplexityNumeric(t *testing.T) {
	g, err := secureotp.New(secret, secureotp.WithComplexity(secureotp.Numeric))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, _ := g.Generate(time.Unix(59, 0))
	for _, ch := range otp {
		if ch < '0' || ch > '9' {
			t.Errorf("non-numeric character %q in OTP %q", ch, otp)
		}
	}
	assertNoRepeat(t, otp, "numeric")
}

func TestComplexityAlphanumeric(t *testing.T) {
	g, err := secureotp.New(secret,
		secureotp.WithLength(8),
		secureotp.WithComplexity(secureotp.Alphanumeric),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, err := g.Generate(time.Unix(59, 0))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(otp) != 8 {
		t.Errorf("expected length 8, got %d", len(otp))
	}
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for _, ch := range otp {
		if !strings.ContainsRune(allowed, ch) {
			t.Errorf("invalid character %q in alphanumeric OTP %q", ch, otp)
		}
	}
	assertNoRepeat(t, otp, "alphanumeric")
}

func TestComplexityCustomCharset(t *testing.T) {
	const charset = "ABCDEFGHIJ" // 10 chars, length 6 ≤ 10
	g, err := secureotp.New(secret,
		secureotp.WithLength(6),
		secureotp.WithCharset(charset),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, err := g.Generate(time.Unix(1234567890, 0))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(otp) != 6 {
		t.Errorf("expected length 6, got %d", len(otp))
	}
	for _, ch := range otp {
		if !strings.ContainsRune(charset, ch) {
			t.Errorf("character %q not in charset %q, OTP=%q", ch, charset, otp)
		}
	}
	assertNoRepeat(t, otp, "custom")
}

// WithCharset must imply Custom complexity without an explicit WithComplexity call.
// With charset "01" (size 2) and length 2, the OTP is a permutation of both chars.
func TestWithCharset_ImpliesCustom(t *testing.T) {
	const charset = "01"
	g, err := secureotp.New(secret, secureotp.WithLength(2), secureotp.WithCharset(charset))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, _ := g.Generate(time.Unix(59, 0))
	if otp != "01" && otp != "10" {
		t.Errorf("expected \"01\" or \"10\", got %q", otp)
	}
	assertNoRepeat(t, otp, "binary charset")
}

// ── Determinism ───────────────────────────────────────────────────────────────

func TestDeterministic_SameTimeSameOTP(t *testing.T) {
	g, err := secureotp.New(secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := time.Unix(1234567890, 0)
	otp1, _ := g.Generate(ts)
	otp2, _ := g.Generate(ts)
	if otp1 != otp2 {
		t.Errorf("non-deterministic: %q != %q", otp1, otp2)
	}
}

func TestDeterministic_SameWindowDifferentNanoseconds(t *testing.T) {
	g, err := secureotp.New(secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	base := int64(1234567800)
	otp1, _ := g.Generate(time.Unix(base, 0))
	otp2, _ := g.Generate(time.Unix(base, 999999999))
	if otp1 != otp2 {
		t.Errorf("nanoseconds must not affect OTP: %q != %q", otp1, otp2)
	}
}

// ── Validate ──────────────────────────────────────────────────────────────────

func TestValidate_CorrectCode(t *testing.T) {
	g, err := secureotp.New(secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := time.Unix(1234567890, 0)
	otp, _ := g.Generate(ts)
	ok, err := g.Validate(otp, ts, 0)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Errorf("Validate returned false for a correct OTP")
	}
}

func TestValidate_WrongCode(t *testing.T) {
	g, err := secureotp.New(secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ok, err := g.Validate("000000", time.Unix(1234567890, 0), 0)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ok {
		t.Error("Validate returned true for an incorrect OTP")
	}
}

func TestValidate_WindowAcceptsAdjacentSteps(t *testing.T) {
	g, err := secureotp.New(secret, secureotp.WithPeriod(30*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	prev := time.Unix(1111111109, 0) // counter 37037036
	curr := time.Unix(1111111111, 0) // counter 37037037

	prevOTP, _ := g.Generate(prev)
	ok, err := g.Validate(prevOTP, curr, 1)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Errorf("window=1 must accept prior-step OTP %q", prevOTP)
	}
}

func TestValidate_WindowRejectsOutOfRange(t *testing.T) {
	g, err := secureotp.New(secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	far := time.Unix(1111111109, 0)
	curr := time.Unix(1111111109+61, 0) // 2 full steps later
	farOTP, _ := g.Generate(far)
	ok, err := g.Validate(farOTP, curr, 1)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ok {
		t.Error("window=1 must not accept an OTP 2 steps away")
	}
}

func TestValidate_NegativeWindowTreatedAsZero(t *testing.T) {
	g, err := secureotp.New(secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := time.Unix(1234567890, 0)
	otp, _ := g.Generate(ts)
	ok, err := g.Validate(otp, ts, -5)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Error("negative window clamped to 0 must still accept the current OTP")
	}
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func TestGenerateBeforeT0_ClampsToZero(t *testing.T) {
	g, err := secureotp.New(secret, secureotp.WithT0(1000))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp1, _ := g.Generate(time.Unix(0, 0))
	otp2, _ := g.Generate(time.Unix(500, 0))
	otp3, _ := g.Generate(time.Unix(999, 0))
	if otp1 != otp2 || otp2 != otp3 {
		t.Errorf("times before T0 must all yield counter=0: %q %q %q", otp1, otp2, otp3)
	}
}

func TestGenerateNow_ReturnsCorrectLength(t *testing.T) {
	const n = 8
	g, err := secureotp.New(secret, secureotp.WithLength(n))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, err := g.GenerateNow()
	if err != nil {
		t.Fatalf("GenerateNow: %v", err)
	}
	if len(otp) != n {
		t.Errorf("expected length %d, got %d (%q)", n, len(otp), otp)
	}
}

// TestLeadingZeroPreserved ensures a leading '0' is not stripped.
// SHA512/T=1111111111 produces "06829471" — starts with 0.
func TestLeadingZeroPreserved(t *testing.T) {
	g, err := secureotp.New(secret,
		secureotp.WithLength(8),
		secureotp.WithHash(secureotp.SHA512),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otp, err := g.Generate(time.Unix(1111111111, 0))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if otp != "06829471" {
		t.Errorf("got %q, want \"06829471\" (leading zero must be preserved)", otp)
	}
}
