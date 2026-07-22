package memory_test

import (
	"context"
	"testing"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/conformance"
	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/memory"
)

// The reference implementation is held to the same suite every host is. If the
// suite and the reference disagree, one of them is wrong and it is worth
// finding out which before anyone builds against either.
func TestConformance(t *testing.T) {
	var current *memory.Store
	conformance.Run(t, conformance.Harness{
		NewStore: func(t conformance.TB) boundedauth.Store {
			current = memory.New()
			return current
		},
		Write: func(ctx context.Context, key string) error {
			return current.Put(ctx, key, []byte("effect"))
		},
		Committed: func(t conformance.TB, key string) bool {
			_, ok := current.Get(key)
			return ok
		},
		Consumed: func(t conformance.TB, id string) bool {
			_, ok := current.Consumption(id)
			return ok
		},
	})
}

// A write attempted outside an effect is refused rather than silently applied,
// which is what a host doing it on its own connection would be doing.
func TestPutOutsideAnEffectIsRefused(t *testing.T) {
	s := memory.New()
	if err := s.Put(context.Background(), "k", []byte("v")); err != memory.ErrNoTransaction {
		t.Fatalf("got %v, want ErrNoTransaction", err)
	}
	if _, ok := s.Get("k"); ok {
		t.Fatal("a write outside a transaction was applied")
	}
}
