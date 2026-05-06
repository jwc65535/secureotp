# secureotp

A Go package that generates Time-based One-Time Passwords (TOTP) with a
**no-repeat** character guarantee: every character in the output is drawn
without replacement from the configured pool, so no character ever appears
twice in the same token.

## Features

- Configurable **length**, **character set**, **time-step duration**, and **HMAC algorithm**
- Three built-in character pools: numeric (`0–9`), alphanumeric (`A–Z 0–9`), or a caller-supplied custom set
- No-repeat guarantee enforced at construction time — invalid configurations are rejected before any token is generated
- Timing-attack-resistant validation via `crypto/subtle` constant-time comparison
- Zero external dependencies — only the Go standard library

## Algorithm

```
counter  =  floor( (unix(now) − T0) / step )

stream   =  HMAC(secret, counter ∥ blockNo)   ← repeated as needed

pool     =  copy of charset
for i in 0..length-1:
    j        =  i + unbiased_random(len(pool) − i, stream)
    swap pool[i], pool[j]
    output[i] =  pool[i]
```

A counter-mode HMAC byte stream (keyed on `secret ∥ counter`) feeds a
Fisher-Yates partial shuffle over the charset.  Rejection sampling eliminates
modulo bias.  The same counter always produces the same token; advancing the
clock by one step produces a statistically independent token.

## Installation

```bash
go get jwc65535/secureotp
```

## Quick start

```go
import "jwc65535/secureotp"

secret := []byte("your-shared-secret")

// Create a generator — defaults: 6-digit numeric, 30 s window, HMAC-SHA-1.
g, err := secureotp.New(secret)

// Generate a token for right now.
otp, err := g.GenerateNow()

// Validate an incoming token, tolerating ±1 time-step of clock drift.
ok, err := g.Validate(otp, time.Now(), 1)
```

## Configuration

All options are passed to `New` as functional options.

| Option | Default | Description |
|---|---|---|
| `WithLength(n)` | `6` | Number of characters. Must be ≤ charset size. |
| `WithComplexity(c)` | `Numeric` | `Numeric` · `Alphanumeric` · `Custom` |
| `WithCharset(s)` | — | Custom pool; implies `Custom`. Must be duplicate-free. |
| `WithPeriod(d)` | `30s` | How long each token is valid. |
| `WithHash(h)` | `SHA1` | `SHA1` · `SHA256` · `SHA512` |
| `WithT0(t0)` | `0` | Unix epoch reference (RFC 6238 T0). |

### Character pool sizes

| Complexity | Pool | Max length |
|---|---|---|
| `Numeric` | `0123456789` | 10 |
| `Alphanumeric` | `A–Z 0–9` | 36 |
| `Custom` | caller-defined | `len(charset)` |

Requesting a length greater than the pool size is an error returned by `New`.

## Examples

```go
secret := []byte("supersecretkey42")

// 8-digit numeric, 60-second window
g, _ := secureotp.New(secret,
    secureotp.WithLength(8),
    secureotp.WithPeriod(60*time.Second),
)

// 6-char alphanumeric token, HMAC-SHA-256
g, _ = secureotp.New(secret,
    secureotp.WithLength(6),
    secureotp.WithComplexity(secureotp.Alphanumeric),
    secureotp.WithHash(secureotp.SHA256),
)

// 16-character token from a hex-digit charset (full permutation)
g, _ = secureotp.New(secret,
    secureotp.WithLength(16),
    secureotp.WithCharset("0123456789ABCDEF"),
)

// Validate with a ±1-step clock-drift window
ok, err := g.Validate(incoming, time.Now(), 1)
```

### Sample output

```
Default (6-digit, 30 s, SHA-1):       425187
8-digit, 60 s window:                  90461278
Alphanumeric (A–Z0–9), SHA-256:        5U3Y79
Custom charset (hex digits):           A51CEF0D8397462B
```

Every token has distinct characters — no digit or letter repeats within a
single token.

## API reference

```go
// New constructs a Generator. Returns an error if the secret is empty,
// any option is invalid, or length > charset size.
func New(secret []byte, opts ...Option) (*Generator, error)

// Generate returns a token for the given time instant.
func (g *Generator) Generate(t time.Time) (string, error)

// GenerateNow returns a token for the current time.
func (g *Generator) GenerateNow() (string, error)

// Validate reports whether code is valid for any time step within
// ±window steps of t. Comparison is constant-time.
func (g *Generator) Validate(code string, t time.Time, window int) (bool, error)
```

## Security notes

**Secret management** — treat the shared secret like a private key. Store it
in a secrets manager or environment variable; never hard-code it or log it.

**Timing attacks** — `Validate` uses `hmac.Equal` (backed by
`crypto/subtle.ConstantTimeCompare`) so comparison time does not vary with how
many characters match, preventing oracle attacks.

**No-repeat vs entropy** — the no-repeat constraint slightly reduces the token
space compared to sampling with replacement (e.g., 10 P 6 = 151 200 ordered
selections vs 10⁶ = 1 000 000).  For typical OTP lengths this is an
acceptable trade-off; increase the length or use a larger charset if higher
entropy is required.

**Window tolerance** — a drift window of 1 is usually sufficient. Wider
windows increase the attack surface; values above 2 are not recommended.

## Testing

```bash
go test ./secureotp/...
```

The test suite includes:

- **Pinned output tests** — 18 deterministic vectors across SHA-1, SHA-256, and SHA-512 that lock the algorithm to known outputs
- **No-repeat property tests** — verify the uniqueness guarantee for all complexity modes and at the full-permutation boundary
- **Configuration validation** — empty secret, invalid length/period, duplicate charset characters, length-exceeds-charset
- **Validate correctness** — correct code, wrong code, window boundary, negative window clamping
- **Determinism** — same time instant and same 30-second window both produce identical tokens
- **Edge cases** — times before T0, leading-zero preservation, `GenerateNow` length
