// Package postgres is a reference [boundedauth.Store] on PostgreSQL.
//
// It is a separate Go module from the core deliberately. A verifier embedded in
// someone else's service should not inherit a database driver because this
// repository happens to ship one, and the core's zero-dependency property is
// worth more than the convenience of a single module.
//
// # How the guarantee is obtained
//
// Everything rests on one transaction:
//
//	BEGIN
//	  INSERT INTO boundedauth_consumptions (jti, ...)   -- primary key
//	  <the effect runs here, on this transaction>
//	COMMIT
//
// Single use comes from the primary key rather than from a read. There is no
// SELECT to check whether the credential was spent, because a check followed by
// an insert is two operations with a gap between them, and the gap is the
// double spend. The insert either succeeds or raises a unique violation, and
// PostgreSQL resolves the race internally: a second inserter blocks on the
// first one's uncommitted row and then, when it commits, sees the violation.
//
// Atomicity comes from the effect running on the same transaction. The host
// gets it with [Tx], and if the host ignores that and opens its own connection,
// the conformance suite fails — correctly, because the guarantee would be
// absent however the code reads.
//
// Rollback needs no special handling and that is the point of the arrangement:
// if the effect returns an error, the transaction is rolled back, and the
// consumption row goes with it. The credential is spendable again because it
// was never durably spent, so a customer whose payment failed is not asked to
// authorise it a second time.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// uniqueViolation is the SQLSTATE for a duplicate key.
const uniqueViolation = "23505"

type txKey struct{}

// Tx returns the transaction the current effect is running on.
//
// Host code inside an effect MUST use this rather than its own pool. A write
// issued on another connection commits independently of the credential being
// spent, which is precisely the failure this package exists to prevent, and it
// will look correct in review.
func Tx(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	return tx, ok
}

// MustTx is Tx for code that has no sensible behaviour without a transaction.
func MustTx(ctx context.Context) pgx.Tx {
	tx, ok := Tx(ctx)
	if !ok {
		panic("boundedauth/postgres: no transaction on context; " +
			"this code must run inside a Store.Consume effect")
	}
	return tx
}

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Consume spends the credential and applies the effect, or does neither.
func (s *Store) Consume(ctx context.Context, rec boundedauth.Consumption, effect func(context.Context) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("boundedauth: begin: %w", err)
	}
	// Rollback after a successful commit is a no-op, so this covers every exit
	// path including a panic in the effect.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO boundedauth_consumptions
			(jti, issuer, subject, method, binding, reference, consumed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, rec.ID, rec.Issuer, rec.Subject, string(rec.Method), rec.Binding,
		rec.Reference, rec.ConsumedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			// Refused before the effect runs. A store that performs the effect
			// and then reports the replay has already moved the money.
			return boundedauth.ErrAlreadyConsumed
		}
		return fmt.Errorf("boundedauth: record consumption: %w", err)
	}

	if err := effect(context.WithValue(ctx, txKey{}, tx)); err != nil {
		// Returned unwrapped so callers can match on their own effect errors.
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("boundedauth: commit: %w", err)
	}
	return nil
}

// Consumption returns the record of a spent credential.
//
// This is what an investigation reads. It carries the binding digest, so a
// spent credential can be tied to the transaction it authorised without the
// credential itself being retained — and a credential that is retained is an
// authorisation that is retained.
func (s *Store) Consumption(ctx context.Context, jti string) (boundedauth.Consumption, bool, error) {
	var rec boundedauth.Consumption
	var method string
	err := s.pool.QueryRow(ctx, `
		SELECT jti, issuer, subject, method, binding, reference, consumed_at
		FROM boundedauth_consumptions WHERE jti = $1
	`, jti).Scan(&rec.ID, &rec.Issuer, &rec.Subject, &method, &rec.Binding,
		&rec.Reference, &rec.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return boundedauth.Consumption{}, false, nil
	}
	if err != nil {
		return boundedauth.Consumption{}, false, err
	}
	rec.Method = boundedauth.Method(method)
	return rec, true, nil
}
