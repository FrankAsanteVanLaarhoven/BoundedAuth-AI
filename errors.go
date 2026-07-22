package boundedauth

import "errors"

// Errors are distinct values rather than a single "invalid credential" because
// the difference matters operationally. A binding mismatch means someone tried
// to reuse authority for a different payment and is worth an alert; an expiry
// means a customer took too long and is worth a retry. Collapsing them into one
// error makes the first invisible inside the noise of the second.
var (
	ErrMalformed         = errors.New("boundedauth: credential malformed")
	ErrBadSignature      = errors.New("boundedauth: signature invalid")
	ErrUntrustedIssuer   = errors.New("boundedauth: issuer not trusted")
	ErrWrongVersion      = errors.New("boundedauth: version not recognised")
	ErrExpired           = errors.New("boundedauth: credential expired")
	ErrNotYetValid       = errors.New("boundedauth: credential not yet valid")
	ErrLifetimeTooLong   = errors.New("boundedauth: lifetime exceeds the permitted maximum")
	ErrTestMethodRefused = errors.New("boundedauth: test authenticator refused; set AllowTestMethod to permit it")

	// ErrBindingMismatch means the credential authorises a different
	// transaction. This is the one to alert on.
	ErrBindingMismatch = errors.New("boundedauth: credential is not bound to this transaction")

	// ErrAlreadyConsumed means the credential was already spent. Returned by a
	// Store, not by verification.
	ErrAlreadyConsumed = errors.New("boundedauth: credential already consumed")
)
