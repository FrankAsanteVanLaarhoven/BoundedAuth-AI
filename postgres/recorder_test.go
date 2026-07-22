package postgres_test

import (
	"sync"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/conformance"
)

// recorder stands in for *testing.T so a conformance check can fail without
// failing the surrounding test, which is how the suite is checked against a
// store that is deliberately wrong.
type recorder struct {
	mu     sync.Mutex
	failed bool
}

type abort struct{}

func (r *recorder) Helper()               {}
func (r *recorder) fail()                 { r.mu.Lock(); r.failed = true; r.mu.Unlock() }
func (r *recorder) Error(...any)          { r.fail() }
func (r *recorder) Errorf(string, ...any) { r.fail() }
func (r *recorder) Fatal(...any)          { r.fail(); panic(abort{}) }
func (r *recorder) Fatalf(string, ...any) { r.fail(); panic(abort{}) }

func runCheck(c conformance.Check, h conformance.Harness) (failed bool) {
	defer func() {
		if v := recover(); v != nil {
			if _, ok := v.(abort); !ok {
				panic(v)
			}
		}
	}()
	r := &recorder{}
	defer func() { failed = r.failed }()
	c.Run(r, h)
	return r.failed
}
