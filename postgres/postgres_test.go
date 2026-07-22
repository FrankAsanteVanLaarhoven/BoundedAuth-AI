package postgres_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/conformance"
	pgstore "github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

const effectsTable = `
CREATE TABLE IF NOT EXISTS boundedauth_conformance_effects (
    key   TEXT PRIMARY KEY,
    value BYTEA NOT NULL
);`

func pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("BOUNDEDAUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("BOUNDEDAUTH_TEST_DATABASE_URL not set; this test needs a real PostgreSQL " +
			"because what it checks is a property of the transaction, not of the code")
	}
	p, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(p.Close)

	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{string(schema), effectsTable} {
		if _, err := p.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	return p
}

func reset(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	// TRUNCATE rather than DELETE: the consumption table refuses DELETE, which
	// is the point of it.
	if _, err := p.Exec(context.Background(),
		`TRUNCATE boundedauth_consumptions, boundedauth_conformance_effects`); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

// The reference implementation is held to the same suite every host is.
func TestConformance(t *testing.T) {
	p := pool(t)
	ctx := context.Background()

	conformance.Run(t, conformance.Harness{
		NewStore: func(tb conformance.TB) boundedauth.Store {
			reset(t, p)
			return pgstore.New(p)
		},
		// The effect writes on the transaction Consume opened. This is the
		// whole contract, expressed in one line.
		Write: func(ctx context.Context, key string) error {
			_, err := pgstore.MustTx(ctx).Exec(ctx,
				`INSERT INTO boundedauth_conformance_effects (key, value) VALUES ($1, $2)`,
				key, []byte("effect"))
			return err
		},
		Committed: func(tb conformance.TB, key string) bool {
			var n int
			if err := p.QueryRow(ctx,
				`SELECT count(*) FROM boundedauth_conformance_effects WHERE key = $1`,
				key).Scan(&n); err != nil {
				tb.Fatalf("committed: %v", err)
			}
			return n == 1
		},
		Consumed: func(tb conformance.TB, id string) bool {
			var n int
			if err := p.QueryRow(ctx,
				`SELECT count(*) FROM boundedauth_consumptions WHERE jti = $1`, id).Scan(&n); err != nil {
				tb.Fatalf("consumed: %v", err)
			}
			return n == 1
		},
	})
}

// The same store, with the effect writing on the pool instead of the
// transaction — the mistake that is easiest to make and hardest to see, since
// the code reads identically and every ordinary test still passes.
//
// This is here so the suite's usefulness against a real database is
// demonstrated rather than assumed.
func TestSuiteCatchesAnEffectOnTheWrongConnection(t *testing.T) {
	p := pool(t)
	ctx := context.Background()

	h := conformance.Harness{
		NewStore: func(tb conformance.TB) boundedauth.Store {
			reset(t, p)
			return pgstore.New(p)
		},
		Write: func(ctx context.Context, key string) error {
			// The defect: the host's own pool, not pgstore.MustTx(ctx).
			_, err := p.Exec(ctx,
				`INSERT INTO boundedauth_conformance_effects (key, value) VALUES ($1, $2)`,
				key, []byte("effect"))
			return err
		},
		Committed: func(tb conformance.TB, key string) bool {
			var n int
			_ = p.QueryRow(ctx,
				`SELECT count(*) FROM boundedauth_conformance_effects WHERE key = $1`, key).Scan(&n)
			return n == 1
		},
		Consumed: func(tb conformance.TB, id string) bool {
			var n int
			_ = p.QueryRow(ctx,
				`SELECT count(*) FROM boundedauth_consumptions WHERE jti = $1`, id).Scan(&n)
			return n == 1
		},
	}

	caught := map[string]bool{}
	for _, c := range conformance.Checks {
		if runCheck(c, h) {
			caught[c.Name] = true
		}
	}
	if !caught["FailedEffectRollsBackItsOwnWrite"] {
		t.Error("an effect writing on a connection unrelated to the credential passed; " +
			"the suite does not detect the mistake it exists to detect")
	}
	if len(caught) == len(conformance.Checks) {
		t.Error("every check failed; the suite is not discriminating")
	}
	t.Logf("caught %d of %d checks", len(caught), len(conformance.Checks))
}

// Consumption records are evidence. Editing one rewrites the account of who
// authorised what; deleting one makes a spent credential spendable again.
func TestConsumptionRecordsAreImmutable(t *testing.T) {
	p := pool(t)
	ctx := context.Background()
	reset(t, p)

	s := pgstore.New(p)
	rec := boundedauth.Consumption{
		ID: "cred-immutable", Issuer: "issuer.test", Subject: "user:alice",
		Method: boundedauth.MethodPasskey, Binding: "digest", Reference: "txn-1",
		ConsumedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
	if err := s.Consume(ctx, rec, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("consume: %v", err)
	}

	if _, err := p.Exec(ctx,
		`UPDATE boundedauth_consumptions SET binding = 'other' WHERE jti = $1`, rec.ID); err == nil {
		t.Error("a consumption record was altered")
	}
	if _, err := p.Exec(ctx,
		`DELETE FROM boundedauth_consumptions WHERE jti = $1`, rec.ID); err == nil {
		t.Error("a consumption record was deleted; the credential would be spendable again")
	}

	got, found, err := s.Consumption(ctx, rec.ID)
	if err != nil || !found {
		t.Fatalf("read back: found=%v err=%v", found, err)
	}
	if got.Binding != "digest" || got.Method != boundedauth.MethodPasskey {
		t.Fatalf("record came back as %+v", got)
	}
}

// A panic inside an effect must not leave the credential spent or a
// half-finished transaction holding locks.
func TestPanicInAnEffectDoesNotSpendTheCredential(t *testing.T) {
	p := pool(t)
	ctx := context.Background()
	reset(t, p)
	s := pgstore.New(p)

	rec := boundedauth.Consumption{
		ID: "cred-panic", Issuer: "i", Subject: "s", Method: boundedauth.MethodPasskey,
		Binding: "d", Reference: "r", ConsumedAt: time.Unix(1_700_000_000, 0).UTC(),
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic did not propagate")
			}
		}()
		_ = s.Consume(ctx, rec, func(context.Context) error { panic("effect exploded") })
	}()

	if _, found, _ := s.Consumption(ctx, rec.ID); found {
		t.Fatal("the credential was spent by an effect that panicked")
	}
	// And the store still works, so no transaction was left open.
	if err := s.Consume(ctx, rec, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("the store was unusable after a panic: %v", err)
	}
}

func TestEffectErrorReachesTheCallerUnwrapped(t *testing.T) {
	p := pool(t)
	ctx := context.Background()
	reset(t, p)

	sentinel := errors.New("rail declined")
	err := pgstore.New(p).Consume(ctx, boundedauth.Consumption{
		ID: "cred-err", Issuer: "i", Subject: "s", Method: boundedauth.MethodPasskey,
		Binding: "d", Reference: "r", ConsumedAt: time.Unix(1_700_000_000, 0).UTC(),
	}, func(context.Context) error { return sentinel })

	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v; a caller cannot tell why its own effect failed", err)
	}
	if strings.Contains(err.Error(), "boundedauth") {
		t.Errorf("the effect's error was wrapped in store detail: %v", err)
	}
}
