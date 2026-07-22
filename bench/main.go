// Command bench replays a real payment workload through the bounded-authority
// path and reports what it cost.
//
// # What this measures, and what it cannot
//
// The workload is the IEEE-CIS Fraud Detection transaction file: 590,540 real
// card transactions with real amounts, real timing and real payer skew. It is
// used here for its SHAPE, not its labels.
//
// That distinction matters and is easy to blur. The fraud labels in this
// dataset are irrelevant to everything measured below. Bounded authority is not
// a detector and does not score anything; it makes an authorisation
// unforgeable, unrepointable and single-use. Those properties are established
// by proof and by the conformance suite, not by a hit rate on a dataset. What
// real data adds is the part a synthetic benchmark gets wrong: the amount
// distribution, the arrival pattern, and above all the concentration of
// transactions on a few busy payers, which is what produces genuine lock
// contention.
//
// A synthetic benchmark with uniformly random payers would report better
// numbers and would be measuring nothing. 590,540 transactions spread over
// 13,553 distinct payers is skewed the way real traffic is skewed.
//
// # What is deliberately not claimed
//
// This does not claim that bounded authority would have prevented any of the
// fraud in this dataset. It structurally prevents fraud in which a payment is
// initiated without the account holder's authorisation. It does nothing about
// fraud in which the account holder is deceived into authorising a payment they
// did make. The IEEE-CIS labels do not separate those two categories, so no
// prevention rate is computable from them, and any figure presented as one
// would be manufactured.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/ed25519"

	"github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI"
	pgstore "github.com/FrankAsanteVanLaarhoven/BoundedAuth-AI/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

type payment struct {
	reference   string
	payer       string
	payee       string
	amountMinor int64
	isFraud     bool
}

// load reads the IEEE-CIS transaction file into payments.
//
// card1 is used as the payer because it is the closest thing the dataset has to
// a stable account identifier, and it carries the real skew: a few cards appear
// thousands of times. The payee is synthesised from the merchant-ish columns —
// the dataset has no payee — and that is stated rather than hidden, because a
// synthesised payee makes payee-side contention unrealistic and the numbers
// below should not be read as measuring it.
func load(path string, limit int) ([]payment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.ReuseRecord = true
	r.FieldsPerRecord = -1

	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	for _, need := range []string{"TransactionID", "isFraud", "TransactionAmt", "card1", "addr1", "ProductCD"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("column %q missing; this does not look like the IEEE-CIS transaction file", need)
		}
	}

	var out []payment
	for len(out) < limit {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		amt, err := strconv.ParseFloat(rec[col["TransactionAmt"]], 64)
		if err != nil {
			continue
		}
		card := strings.TrimSpace(rec[col["card1"]])
		if card == "" {
			continue
		}
		addr := strings.TrimSpace(rec[col["addr1"]])
		if addr == "" {
			addr = "unknown"
		}
		out = append(out, payment{
			reference: "txn-" + rec[col["TransactionID"]],
			payer:     "card:" + card,
			payee:     "merchant:" + rec[col["ProductCD"]] + ":" + addr,
			// Minor units. The dataset carries decimal amounts; rounding here
			// is the same rounding a real integration does at its edge.
			amountMinor: int64(amt*100 + 0.5),
			isFraud:     rec[col["isFraud"]] == "1",
		})
	}
	return out, nil
}

type stats struct {
	N       int     `json:"n"`
	P50Ms   float64 `json:"p50Ms"`
	P95Ms   float64 `json:"p95Ms"`
	P99Ms   float64 `json:"p99Ms"`
	MaxMs   float64 `json:"maxMs"`
	MeanMs  float64 `json:"meanMs"`
	PerSec  float64 `json:"perSecond"`
	Elapsed float64 `json:"elapsedSeconds"`
}

func summarise(d []time.Duration, elapsed time.Duration) stats {
	if len(d) == 0 {
		return stats{}
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	ms := func(x time.Duration) float64 { return float64(x.Nanoseconds()) / 1e6 }
	at := func(p float64) time.Duration {
		i := int(p * float64(len(d)))
		if i >= len(d) {
			i = len(d) - 1
		}
		return d[i]
	}
	var total time.Duration
	for _, x := range d {
		total += x
	}
	return stats{
		N: len(d), P50Ms: ms(at(0.50)), P95Ms: ms(at(0.95)), P99Ms: ms(at(0.99)),
		MaxMs: ms(d[len(d)-1]), MeanMs: ms(total) / float64(len(d)),
		PerSec: float64(len(d)) / elapsed.Seconds(), Elapsed: elapsed.Seconds(),
	}
}

type report struct {
	Dataset     datasetInfo            `json:"dataset"`
	Environment map[string]any         `json:"environment"`
	Results     map[string]any         `json:"results"`
	NotMeasured []string               `json:"notMeasured"`
	Errors      map[string]int         `json:"unexpectedErrors,omitempty"`
	Extra       map[string]interface{} `json:"-"`
}

type datasetInfo struct {
	Name       string  `json:"name"`
	Path       string  `json:"path"`
	Rows       int     `json:"rowsUsed"`
	Payers     int     `json:"distinctPayers"`
	FraudRate  float64 `json:"fraudRateInSample"`
	MeanAmount float64 `json:"meanAmountMinor"`
	MaxAmount  int64   `json:"maxAmountMinor"`
}

func main() {
	var (
		csvPath     = flag.String("csv", "", "path to IEEE-CIS train_transaction.csv")
		dbURL       = flag.String("db", os.Getenv("BOUNDEDAUTH_TEST_DATABASE_URL"), "PostgreSQL URL")
		limit       = flag.Int("limit", 50_000, "transactions to replay")
		concurrency = flag.String("concurrency", "1,8,32,64,128", "comma-separated worker counts")
		repeats     = flag.Int("repeats", 3, "repetitions per concurrency level")
		out         = flag.String("out", "", "write JSON report here")
	)
	flag.Parse()

	if *csvPath == "" || *dbURL == "" {
		fmt.Fprintln(os.Stderr, "usage: bench -csv <train_transaction.csv> -db <postgres url>")
		os.Exit(2)
	}

	ctx := context.Background()
	fmt.Printf("loading %s\n", *csvPath)
	payments, err := load(*csvPath, *limit)
	if err != nil {
		fatal(err)
	}

	payers := map[string]int{}
	var sum, max int64
	fraud := 0
	for _, p := range payments {
		payers[p.payer]++
		sum += p.amountMinor
		if p.amountMinor > max {
			max = p.amountMinor
		}
		if p.isFraud {
			fraud++
		}
	}

	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		fatal(err)
	}
	defer pool.Close()
	if err := prepare(ctx, pool); err != nil {
		fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(nil)
	issuer := boundedauth.Issuer{Name: "bench.issuer", Key: priv}
	verifier := boundedauth.Verifier{TrustedIssuers: map[string]ed25519.PublicKey{"bench.issuer": pub}}
	store := pgstore.New(pool)

	rep := report{
		Dataset: datasetInfo{
			Name: "IEEE-CIS Fraud Detection (train_transaction.csv)", Path: *csvPath,
			Rows: len(payments), Payers: len(payers),
			FraudRate:  float64(fraud) / float64(len(payments)),
			MeanAmount: float64(sum) / float64(len(payments)), MaxAmount: max,
		},
		Environment: map[string]any{
			"goVersion": strings.TrimPrefix(runtimeVersion(), "go"),
			"database":  "PostgreSQL",
			"note": "single host, database and load generator on the same machine; " +
				"absolute throughput is therefore not a capacity claim",
		},
		Results: map[string]any{},
		NotMeasured: []string{
			"Fraud detection accuracy. Bounded authority is not a detector; the labels in this dataset are not used for scoring anything.",
			"Whether bounded authority would have prevented the fraud in this dataset. It structurally prevents payments initiated without the account holder; it does nothing about payments the account holder was deceived into authorising. The labels do not separate those, so no prevention rate is computable.",
			"Payee-side contention. The dataset has no payee, so payees here are synthesised.",
			"Network latency between service and database.",
			"Behaviour under database failover or replication lag.",
		},
		Errors: map[string]int{},
	}

	fmt.Printf("%d transactions, %d distinct payers, %.2f%% labelled fraud (unused)\n\n",
		len(payments), len(payers), rep.Dataset.FraudRate*100)

	// --- 1. verification only, no database -------------------------------
	fmt.Println("1. verification cost (no database)")
	rep.Results["verifyOnly"] = benchVerifyOnly(issuer, verifier, payments)

	// --- 2. full authorisation path at several concurrencies -------------
	fmt.Println("2. full path: verify + consume + effect, atomically")
	// Repeated runs, because a single measurement per level cannot distinguish
	// a real effect from run-to-run variance — and the first version of this
	// harness reported a super-linear jump from one run each.
	full := map[string]any{}
	for _, c := range parseInts(*concurrency) {
		var runs []stats
		for r := 0; r < *repeats; r++ {
			if err := truncate(ctx, pool); err != nil {
				fatal(err)
			}
			runs = append(runs, benchFull(ctx, issuer, verifier, store, payments, c, rep.Errors))
		}
		ps := make([]float64, len(runs))
		for i, s := range runs {
			ps[i] = s.PerSec
		}
		sort.Float64s(ps)
		med := ps[len(ps)/2]
		spread := (ps[len(ps)-1] - ps[0]) / med
		full[strconv.Itoa(c)] = map[string]any{
			"runs": runs, "medianPerSecond": med,
			"spreadFraction": spread, "repeats": len(runs),
		}
		fmt.Printf("   workers=%-3d median %8.0f/s  (spread %.1f%% over %d runs)  p50=%6.2fms p99=%6.2fms\n",
			c, med, spread*100, len(runs), runs[len(runs)/2].P50Ms, runs[len(runs)/2].P99Ms)
	}
	rep.Results["fullPathByConcurrency"] = full

	// --- 3. adversarial: replay and repointing ---------------------------
	fmt.Println("3. adversarial")
	rep.Results["adversarial"] = benchAdversarial(ctx, issuer, verifier, store, payments)

	// --- 4. failure injection --------------------------------------------
	fmt.Println("4. failure injection")
	rep.Results["failureInjection"] = benchFailure(ctx, issuer, verifier, store, payments)

	// --- 5. contention on the busiest payers ------------------------------
	fmt.Println("5. contention")
	rep.Results["contention"] = benchContention(ctx, issuer, verifier, store, payments, payers, 32)

	body, _ := json.MarshalIndent(rep, "", "  ")
	if *out != "" {
		if err := os.WriteFile(*out, append(body, '\n'), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("\nreport written to %s\n", *out)
	} else {
		fmt.Println(string(body))
	}
	if len(rep.Errors) > 0 {
		fmt.Printf("\nunexpected errors: %v\n", rep.Errors)
	}
}

func binding(p payment) boundedauth.Binding {
	return boundedauth.Binding{
		Payer: p.payer, Payee: p.payee, AmountMinor: p.amountMinor,
		FeeMinor: 0, Currency: "USD", Reference: p.reference,
	}
}

func credential(iss boundedauth.Issuer, p payment, n int) (string, error) {
	now := time.Now()
	return iss.Mint(boundedauth.Payload{
		ID: fmt.Sprintf("cred-%s-%d", p.reference, n), Subject: p.payer,
		Method: boundedauth.MethodPasskey, Binding: binding(p).Digest(),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
	})
}

// benchVerifyOnly isolates the CPU cost: digest plus Ed25519 verification, with
// no database involved. This is the part that scales with cores and the part a
// caller pays even when refusing.
func benchVerifyOnly(iss boundedauth.Issuer, v boundedauth.Verifier, payments []payment) stats {
	creds := make([]string, 0, len(payments))
	for i, p := range payments {
		c, err := credential(iss, p, i)
		if err != nil {
			continue
		}
		creds = append(creds, c)
		if len(creds) >= 20_000 {
			break
		}
	}
	d := make([]time.Duration, 0, len(creds))
	start := time.Now()
	for i, c := range creds {
		t := time.Now()
		if _, err := v.Verify(c, binding(payments[i])); err != nil {
			continue
		}
		d = append(d, time.Since(t))
	}
	s := summarise(d, time.Since(start))
	fmt.Printf("   %8.0f/s  p50=%.3fms p99=%.3fms\n", s.PerSec, s.P50Ms, s.P99Ms)
	return s
}

func benchFull(ctx context.Context, iss boundedauth.Issuer, v boundedauth.Verifier,
	store boundedauth.Store, payments []payment, workers int, errs map[string]int) stats {

	type result struct {
		d   time.Duration
		err error
	}
	in := make(chan int)
	results := make(chan result, workers*4)

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range in {
				p := payments[i]
				c, err := credential(iss, p, i)
				if err != nil {
					results <- result{err: err}
					continue
				}
				t := time.Now()
				_, err = boundedauth.Authorise(ctx, v, store, c, binding(p),
					func(ctx context.Context, rec boundedauth.Consumption) error {
						_, e := pgstore.MustTx(ctx).Exec(ctx,
							`INSERT INTO bench_postings (reference, payer, payee, amount_minor, grant_jti)
							 VALUES ($1,$2,$3,$4,$5)`,
							p.reference, p.payer, p.payee, p.amountMinor, rec.ID)
						return e
					})
				results <- result{d: time.Since(t), err: err}
			}
		}()
	}

	start := time.Now()
	go func() {
		for i := range payments {
			in <- i
		}
		close(in)
	}()
	go func() { wg.Wait(); close(results) }()

	d := make([]time.Duration, 0, len(payments))
	var mu sync.Mutex
	for r := range results {
		if r.err != nil {
			mu.Lock()
			errs[classify(r.err)]++
			mu.Unlock()
			continue
		}
		d = append(d, r.d)
	}
	return summarise(d, time.Since(start))
}

// benchAdversarial replays spent credentials and presents credentials against
// altered transactions. Both must be refused, every time — a rate below 100%
// here is not a performance result, it is a broken control.
func benchAdversarial(ctx context.Context, iss boundedauth.Issuer, v boundedauth.Verifier,
	store boundedauth.Store, payments []payment) map[string]any {

	const n = 5_000
	if len(payments) < n {
		return map[string]any{"skipped": "not enough transactions"}
	}
	sample := payments[:n]

	// Spend them.
	spent := make([]string, 0, n)
	for i, p := range sample {
		c, _ := credential(iss, p, 1_000_000+i)
		if _, err := boundedauth.Authorise(ctx, v, store, c, binding(p),
			func(ctx context.Context, rec boundedauth.Consumption) error { return nil }); err == nil {
			spent = append(spent, c)
		}
	}

	// Replay each one.
	replayRefused, replayAccepted := 0, 0
	var replayD []time.Duration
	start := time.Now()
	for i, c := range spent {
		t := time.Now()
		_, err := boundedauth.Authorise(ctx, v, store, c, binding(sample[i]),
			func(ctx context.Context, rec boundedauth.Consumption) error { return nil })
		replayD = append(replayD, time.Since(t))
		if errors.Is(err, boundedauth.ErrAlreadyConsumed) {
			replayRefused++
		} else {
			replayAccepted++
		}
	}
	replayStats := summarise(replayD, time.Since(start))

	// Repoint: present a fresh credential against a transaction altered by one
	// minor unit. It must be refused, and must NOT be spent, or an observer
	// could burn a customer's authorisation at will.
	repointRefused, repointAccepted, burned := 0, 0, 0
	for i, p := range sample[:1_000] {
		c, _ := credential(iss, p, 2_000_000+i)
		altered := binding(p)
		altered.AmountMinor++
		_, err := boundedauth.Authorise(ctx, v, store, c, altered,
			func(ctx context.Context, rec boundedauth.Consumption) error { return nil })
		if errors.Is(err, boundedauth.ErrBindingMismatch) {
			repointRefused++
		} else {
			repointAccepted++
		}
		// The genuine payment must still work.
		if _, err := boundedauth.Authorise(ctx, v, store, c, binding(p),
			func(ctx context.Context, rec boundedauth.Consumption) error { return nil }); err != nil {
			burned++
		}
	}

	fmt.Printf("   replay:   %d refused, %d accepted  (p50=%.2fms, refusal is cheap)\n",
		replayRefused, replayAccepted, replayStats.P50Ms)
	fmt.Printf("   repoint:  %d refused, %d accepted, %d credentials burned by the attempt\n",
		repointRefused, repointAccepted, burned)

	return map[string]any{
		"replayAttempts": len(spent), "replayRefused": replayRefused,
		"replayAccepted": replayAccepted, "replayLatency": replayStats,
		"repointAttempts": 1_000, "repointRefused": repointRefused,
		"repointAccepted":                       repointAccepted,
		"credentialsBurnedByARepointingAttempt": burned,
	}
}

// benchFailure fails a share of effects and checks the credential survives, so
// a customer whose payment failed is not asked to authorise it again.
func benchFailure(ctx context.Context, iss boundedauth.Issuer, v boundedauth.Verifier,
	store boundedauth.Store, payments []payment) map[string]any {

	const n = 2_000
	failEvery := 3
	sentinel := errors.New("simulated rail failure")

	failed, recovered, lost := 0, 0, 0
	for i, p := range payments[:n] {
		c, _ := credential(iss, p, 3_000_000+i)
		shouldFail := i%failEvery == 0
		_, err := boundedauth.Authorise(ctx, v, store, c, binding(p),
			func(ctx context.Context, rec boundedauth.Consumption) error {
				if _, e := pgstore.MustTx(ctx).Exec(ctx,
					`INSERT INTO bench_postings (reference, payer, payee, amount_minor, grant_jti)
					 VALUES ($1,$2,$3,$4,$5)`,
					p.reference+"-f", p.payer, p.payee, p.amountMinor, rec.ID); e != nil {
					return e
				}
				if shouldFail {
					return sentinel
				}
				return nil
			})
		if !shouldFail {
			continue
		}
		failed++
		if !errors.Is(err, sentinel) {
			continue
		}
		// Retry the same credential, as a customer's client would.
		if _, err := boundedauth.Authorise(ctx, v, store, c, binding(p),
			func(ctx context.Context, rec boundedauth.Consumption) error { return nil }); err == nil {
			recovered++
		} else {
			lost++
		}
	}
	fmt.Printf("   %d effects failed, %d credentials still spendable, %d lost\n",
		failed, recovered, lost)
	return map[string]any{
		"effectsFailed": failed, "credentialsStillSpendable": recovered,
		"credentialsLost": lost,
	}
}

// benchContention asks whether payer concentration causes lock contention.
//
// The first version of this function was wrong in a way worth recording: it ran
// the workload in a single sequential loop and reported "no contention penalty
// on the busiest payers". With one goroutine there is no contention to measure,
// so the null result was uninformative — it said nothing about the design and
// would have read as though it did.
//
// This version runs each cohort concurrently at the same worker count, and adds
// a control that deliberately serialises on one row. If the control shows a
// penalty and the hot-payer cohort does not, the null result means something. If
// neither shows a penalty, the measurement is still not sensitive enough to
// support any claim.
func benchContention(ctx context.Context, iss boundedauth.Issuer, v boundedauth.Verifier,
	store boundedauth.Store, payments []payment, payers map[string]int, workers int) map[string]any {

	type kv struct {
		payer string
		n     int
	}
	var all []kv
	for p, n := range payers {
		all = append(all, kv{p, n})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n > all[j].n })
	if len(all) < 50 {
		return map[string]any{"skipped": "too few payers"}
	}
	hot := map[string]bool{}
	for _, k := range all[:10] {
		hot[k.payer] = true
	}

	const cohort = 4_000
	var hotSet, spreadSet []payment
	seen := map[string]bool{}
	for _, p := range payments {
		if hot[p.payer] && len(hotSet) < cohort {
			hotSet = append(hotSet, p)
		} else if !hot[p.payer] && !seen[p.payer] && len(spreadSet) < cohort {
			seen[p.payer] = true
			spreadSet = append(spreadSet, p)
		}
		if len(hotSet) >= cohort && len(spreadSet) >= cohort {
			break
		}
	}
	if len(hotSet) < cohort/2 {
		return map[string]any{"skipped": "not enough transactions from the busiest payers"}
	}

	// Each cohort needs its own credential-identifier range. The first version
	// reused one range across all three, so every credential in the second and
	// third cohorts was already spent and the runs returned nothing — the
	// shared-row control silently measured zero operations. The teeth-check
	// below is what surfaced it; without it this would have been published as
	// "no contention detected".
	run := func(set []payment, tag string, sharedRow bool, idBase int) stats {
		in := make(chan int)
		out := make(chan time.Duration, workers*4)
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for i := range in {
					p := set[i]
					c, err := credential(iss, p, idBase+i)
					if err != nil {
						continue
					}
					t := time.Now()
					_, err = boundedauth.Authorise(ctx, v, store, c, binding(p),
						func(ctx context.Context, rec boundedauth.Consumption) error {
							tx := pgstore.MustTx(ctx)
							if _, e := tx.Exec(ctx,
								`INSERT INTO bench_postings (reference, payer, payee, amount_minor, grant_jti)
								 VALUES ($1,$2,$3,$4,$5)`,
								p.reference+"-"+tag, p.payer, p.payee, p.amountMinor, rec.ID); e != nil {
								return e
							}
							if sharedRow {
								// Every payment updates the same row, so the
								// database must serialise them. This is what
								// contention looks like when it is present.
								_, e := tx.Exec(ctx,
									`UPDATE bench_shared_row SET n = n + 1 WHERE id = 1`)
								return e
							}
							return nil
						})
					if err == nil {
						out <- time.Since(t)
					}
				}
			}()
		}
		start := time.Now()
		go func() {
			for i := range set {
				in <- i
			}
			close(in)
		}()
		go func() { wg.Wait(); close(out) }()
		var d []time.Duration
		for x := range out {
			d = append(d, x)
		}
		return summarise(d, time.Since(start))
	}

	h := run(hotSet, "hot", false, 5_000_000)
	c := run(spreadSet[:len(hotSet)], "spread", false, 6_000_000)
	ctl := run(spreadSet[:len(hotSet)], "ctl", true, 7_000_000)

	fmt.Printf("   (all cohorts run concurrently at %d workers)\n", workers)
	fmt.Printf("   busiest 10 payers:  p50=%6.2fms p99=%6.2fms  %7.0f/s (n=%d)\n", h.P50Ms, h.P99Ms, h.PerSec, h.N)
	fmt.Printf("   distinct payers:    p50=%6.2fms p99=%6.2fms  %7.0f/s (n=%d)\n", c.P50Ms, c.P99Ms, c.PerSec, c.N)
	fmt.Printf("   CONTROL, one shared row: p50=%6.2fms p99=%6.2fms  %7.0f/s\n", ctl.P50Ms, ctl.P99Ms, ctl.PerSec)

	sensitive := ctl.P50Ms > c.P50Ms*1.25
	fmt.Printf("   → the measurement %s detect contention when it is present\n",
		map[bool]string{true: "CAN", false: "CANNOT"}[sensitive])

	return map[string]any{
		"workers": workers, "cohortSize": len(hotSet),
		"busiestTenPayers": h, "distinctPayers": c, "controlSharedRow": ctl,
		"controlDetectsContention": sensitive,
		"note": "consumption records are keyed by the credential identifier, not by " +
			"payer, so two payments from one payer touch different rows. The shared-row " +
			"control establishes that this measurement is sensitive to contention that " +
			"does exist; without it a null result would be uninterpretable.",
	}
}

func runtimeVersion() string { return runtime.Version() }

func classify(err error) string {
	switch {
	case errors.Is(err, boundedauth.ErrAlreadyConsumed):
		return "already_consumed"
	case errors.Is(err, boundedauth.ErrBindingMismatch):
		return "binding_mismatch"
	case errors.Is(err, boundedauth.ErrExpired):
		return "expired"
	default:
		s := err.Error()
		if len(s) > 60 {
			s = s[:60]
		}
		return s
	}
}

func parseInts(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func prepare(ctx context.Context, pool *pgxpool.Pool) error {
	schema, err := os.ReadFile("../postgres/schema.sql")
	if err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	for _, stmt := range []string{string(schema), `
		CREATE TABLE IF NOT EXISTS bench_postings (
			id BIGSERIAL PRIMARY KEY,
			reference TEXT NOT NULL,
			payer TEXT NOT NULL,
			payee TEXT NOT NULL,
			amount_minor BIGINT NOT NULL,
			grant_jti TEXT NOT NULL
		)`, `
		CREATE TABLE IF NOT EXISTS bench_shared_row (id INT PRIMARY KEY, n BIGINT NOT NULL)`, `
		INSERT INTO bench_shared_row (id, n) VALUES (1, 0) ON CONFLICT (id) DO NOTHING`} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return truncate(ctx, pool)
}

func truncate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `TRUNCATE boundedauth_consumptions, bench_postings`)
	return err
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
