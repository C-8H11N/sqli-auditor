package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// respondSQL writes the response for an already-broken-out injected tail. It is
// shared by the Less-1/2/3 mocks: SQL errors are reflected with HTTP 200 (not
// 500), and a UNION row is only reflected when the leading SELECT is negated.
func respondSQL(w http.ResponseWriter, v, appdbHex string, big bool) {
	switch {
	case strings.Contains(v, "UNION SELECT"):
		if !strings.Contains(v, "AND 1=2") {
			fmt.Fprint(w, "Your Login name:Dumb")
			return
		}
		switch {
		case strings.Contains(v, "information_schema.schemata"):
			if big {
				fmt.Fprint(w, markerPrefix+"db1"+listSeparator+"db2"+listSeparator+"db3"+listSeparator+"db4"+listSeparator+"db5"+listSeparator+"db6"+markerSuffix)
			} else {
				fmt.Fprint(w, markerPrefix+"information_schema"+listSeparator+"appdb"+markerSuffix)
			}
		case strings.Contains(v, "information_schema.tables"):
			if big {
				fmt.Fprint(w, markerPrefix+"t1"+listSeparator+"t2"+listSeparator+"t3"+listSeparator+"t4"+listSeparator+"t5"+listSeparator+"t6"+listSeparator+"t7"+listSeparator+"t8"+markerSuffix)
			} else if strings.Contains(v, appdbHex) {
				fmt.Fprint(w, markerPrefix+"users"+markerSuffix)
			} else {
				fmt.Fprint(w, markerPrefix+markerSuffix)
			}
		case strings.Contains(v, "information_schema.columns"):
			if big {
				fmt.Fprint(w, markerPrefix+"c1"+listSeparator+"c2"+listSeparator+"c3"+listSeparator+"c4"+listSeparator+"c5"+markerSuffix)
			} else if strings.Contains(v, appdbHex) {
				fmt.Fprint(w, markerPrefix+"id"+listSeparator+"username"+markerSuffix)
			} else {
				fmt.Fprint(w, markerPrefix+markerSuffix)
			}
		case strings.Contains(v, "LIMIT"):
			if big {
				fmt.Fprint(w, markerPrefix+"v1\x1fv2"+markerSuffix)
			} else {
				fmt.Fprint(w, markerPrefix+"1\x1fadmin"+markerSuffix)
			}
		case strings.Contains(v, "database()"):
			fmt.Fprint(w, markerPrefix+"appdb"+markerSuffix)
		default:
			// Only columns 1 and 2 are reflected; column 0 (id) is hidden,
			// mirroring the sqli-labs users table.
			fmt.Fprint(w, "Your Login name:sqli_col_01 <br>Your Password:sqli_col_02")
		}
	case strings.Contains(v, "ORDER BY"):
		if orderNumber(v) > 3 {
			fmt.Fprintf(w, "Unknown column '%d' in 'order clause'", orderNumber(v))
		} else {
			fmt.Fprint(w, "normal page for id=1")
		}
	case strings.Contains(v, "AND 1=1"):
		fmt.Fprint(w, "true-branch: condition evaluated true")
	case strings.Contains(v, "AND 1=2"):
		fmt.Fprint(w, "false-branch")
	default:
		fmt.Fprint(w, "normal page for id="+v)
	}
}

// newSQLiLabHandler emulates sqli-labs Less-1 (WHERE id='$id'). A payload only
// breaks out when it closes the single quote; numeric and parenthesized payloads
// stay inside the literal. When big is true the schema is enlarged so the
// request budget is exhausted during enumeration.
func newSQLiLabHandler(big bool) http.HandlerFunc {
	appdbHex := hexSQL("appdb")
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		switch {
		case v == "1":
			fmt.Fprint(w, "normal page for id=1")
		case v == "1'":
			fmt.Fprint(w, "You have an error in your SQL syntax near ''1'' LIMIT 0,1' at line 1")
		case strings.HasPrefix(v, "1'"):
			if strings.HasPrefix(v, "1')") {
				fmt.Fprint(w, "You have an error in your SQL syntax near ')'' at line 1")
			} else {
				respondSQL(w, v, appdbHex, big)
			}
		default:
			fmt.Fprint(w, "no rows")
		}
	}
}

// newSQLiLab returns a local httptest target that emulates a MySQL-backed,
// UNION-injectable endpoint. It inspects the injected query string and replies
// with the matching error signature or marked payload, so the full stack can be
// exercised without a real database.
func newSQLiLab() *httptest.Server {
	return httptest.NewServer(newSQLiLabHandler(false))
}

// newSQLiLabBig returns a target with a large schema so the request budget is
// exhausted during fields enumeration, even at the minimum budget.
func newSQLiLabBig() *httptest.Server {
	return httptest.NewServer(newSQLiLabHandler(true))
}

// newSQLiLabNumericHandler emulates sqli-labs Less-2 (WHERE id=$id). Any payload
// containing a quote is a SQL syntax error; otherwise the value is injected SQL.
func newSQLiLabNumericHandler(big bool) http.HandlerFunc {
	appdbHex := hexSQL("appdb")
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		switch {
		case v == "1":
			fmt.Fprint(w, "normal page for id=1")
		case strings.Contains(v, "'") || strings.Contains(v, `"`):
			fmt.Fprint(w, "You have an error in your SQL syntax near the injected value")
		default:
			respondSQL(w, v, appdbHex, big)
		}
	}
}

// newSQLiLabNumeric returns a local target emulating the numeric sqli-labs
// Less-2 page, where the value is interpolated without quotes.
func newSQLiLabNumeric() *httptest.Server {
	return httptest.NewServer(newSQLiLabNumericHandler(false))
}

// newSQLiLabParenHandler emulates sqli-labs Less-3 (WHERE id=('$id')). Only a
// payload that closes both the quote and the parenthesis breaks out.
func newSQLiLabParenHandler(big bool) http.HandlerFunc {
	appdbHex := hexSQL("appdb")
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		switch {
		case v == "1":
			fmt.Fprint(w, "normal page for id=1")
		case v == "1'":
			fmt.Fprint(w, "You have an error in your SQL syntax near ''1') LIMIT 0,1' at line 1")
		case strings.HasPrefix(v, "1')"):
			respondSQL(w, v, appdbHex, big)
		case strings.HasPrefix(v, "1'"):
			fmt.Fprint(w, "You have an error in your SQL syntax near ')'' at line 1")
		default:
			fmt.Fprint(w, "no rows")
		}
	}
}

// newSQLiLabParen returns a local target emulating the parenthesized sqli-labs
// Less-3 page, where the value is wrapped in ('...').
func newSQLiLabParen() *httptest.Server {
	return httptest.NewServer(newSQLiLabParenHandler(false))
}

// newBlindHandler emulates a target where error-based detection (ORDER BY, DB
// error signatures) works but UNION reflection is unavailable, so the stack must
// fall back to boolean-blind inference of database(). The current database is
// "appdb". True/false branches return distinct bodies.
func newBlindHandler() http.HandlerFunc {
	const dbName = "appdb"
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		switch {
		case v == "1":
			fmt.Fprint(w, "normal page for id=1")
		case v == "1'":
			fmt.Fprint(w, "You have an error in your SQL syntax near ''1'' LIMIT 0,1' at line 1")
		case strings.HasPrefix(v, "1'"):
			if strings.HasPrefix(v, "1')") {
				fmt.Fprint(w, "You have an error in your SQL syntax near ')'' at line 1")
			} else if strings.Contains(v, "UNION SELECT") {
				// UNION is blocked: no marker is ever reflected.
				fmt.Fprint(w, "unrelated page content")
			} else if strings.Contains(v, "ORDER BY") {
				if orderNumber(v) > 3 {
					fmt.Fprintf(w, "Unknown column '%d' in 'order clause'", orderNumber(v))
				} else {
					fmt.Fprint(w, "normal page for id=1")
				}
			} else if blindConditionTrue(v, dbName) {
				fmt.Fprint(w, "true-branch page (distinct length)")
			} else {
				fmt.Fprint(w, "false-branch page")
			}
		default:
			fmt.Fprint(w, "no rows")
		}
	}
}

var blindLengthRegexp = regexp.MustCompile(`LENGTH\(database\(\)\)\s*=\s*(\d+)`)
var blindOrdRegexp = regexp.MustCompile(`ORD\(SUBSTRING\(database\(\),(\d+),1\)\)\s*>\s*(\d+)`)

func blindConditionTrue(v, dbName string) bool {
	switch {
	case strings.Contains(v, "1=1"):
		return true
	case strings.Contains(v, "1=2"):
		return false
	}
	if m := blindLengthRegexp.FindStringSubmatch(v); m != nil {
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		return n == len(dbName)
	}
	if m := blindOrdRegexp.FindStringSubmatch(v); m != nil {
		var pos, mid int
		fmt.Sscanf(m[1], "%d", &pos)
		fmt.Sscanf(m[2], "%d", &mid)
		if pos >= 1 && pos <= len(dbName) {
			return int(dbName[pos-1]) > mid
		}
		return false
	}
	return false
}

var orderRegexp = regexp.MustCompile(`ORDER BY (\d+)`)

func orderNumber(payload string) int {
	m := orderRegexp.FindStringSubmatch(payload)
	if len(m) != 2 {
		return 0
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	return n
}

func findDatabase(report StackReport, name string) *DatabaseResult {
	for i := range report.Databases {
		if report.Databases[i].Name == name {
			return &report.Databases[i]
		}
	}
	return nil
}

func TestRunStackFullPipeline(t *testing.T) {
	server := newSQLiLab()
	defer server.Close()

	report, err := RunStack(context.Background(), StackConfig{Target: server.URL + "/?id=1", RequestBudget: 120, PreviewRows: 3})
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial {
		t.Fatalf("unexpected partial result: %+v", report)
	}
	if len(report.Parameters) != 1 || !report.Parameters[0].Injectable {
		t.Fatalf("expected one injectable parameter, got %+v", report.Parameters)
	}
	p := report.Parameters[0]
	if p.InjectionType == "" {
		t.Fatalf("expected injection type, got %+v", p)
	}
	if p.ColumnCount != 3 {
		t.Fatalf("expected column count 3, got %d", p.ColumnCount)
	}
	if len(p.DisplayColumns) != 2 || p.DisplayColumns[0] != 1 || p.DisplayColumns[1] != 2 {
		t.Fatalf("expected display columns [1 2] (id column hidden), got %v", p.DisplayColumns)
	}

	if len(report.Stages) != len(stageOrder) {
		t.Fatalf("expected %d stages, got %d: %+v", len(stageOrder), len(report.Stages), report.Stages)
	}
	for i, stage := range report.Stages {
		if stage.Key != stageOrder[i] {
			t.Fatalf("stage order mismatch at %d: got %s want %s", i, stage.Key, stageOrder[i])
		}
	}

	db := findDatabase(report, "appdb")
	if db == nil {
		t.Fatalf("expected appdb database, got %+v", report.Databases)
	}
	if len(db.Tables) != 1 || db.Tables[0].Name != "users" {
		t.Fatalf("expected users table, got %+v", db.Tables)
	}
	table := db.Tables[0]
	if len(table.Columns) < 2 {
		t.Fatalf("expected columns, got %v", table.Columns)
	}
	if len(table.Rows) == 0 {
		t.Fatalf("expected preview rows, got %v", table.Rows)
	}
	if table.Rows[0]["id"] != "1" {
		t.Fatalf("unexpected preview row: %v", table.Rows[0])
	}
}

func TestRunStackBudgetExhaustion(t *testing.T) {
	server := newSQLiLabBig()
	defer server.Close()

	report, err := RunStack(context.Background(), StackConfig{Target: server.URL + "/?id=1", RequestBudget: 20, PreviewRows: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial {
		t.Fatalf("expected partial result when budget is exhausted")
	}
	if report.Requests > report.RequestBudget {
		t.Fatalf("request count %d exceeds budget %d", report.Requests, report.RequestBudget)
	}
	hasPartialStage := false
	for _, stage := range report.Stages {
		if stage.Status == StatusPartial {
			hasPartialStage = true
		}
	}
	if !hasPartialStage {
		t.Fatalf("expected at least one partial stage, got %+v", report.Stages)
	}
}

func TestRunStackNoInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "same page for any input")
	}))
	defer server.Close()

	report, err := RunStack(context.Background(), StackConfig{Target: server.URL + "/?id=1", RequestBudget: 60})
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial {
		t.Fatalf("unexpected partial: %+v", report)
	}
	if len(report.Parameters) == 0 || report.Parameters[0].Injectable {
		t.Fatalf("expected non-injectable parameter, got %+v", report.Parameters)
	}
	if len(report.Databases) != 0 {
		t.Fatalf("expected no databases, got %+v", report.Databases)
	}
	// The first stage must be present and the stack must stop cleanly.
	if len(report.Stages) != len(stageOrder) {
		t.Fatalf("expected %d stages, got %d", len(stageOrder), len(report.Stages))
	}
}

func TestRunStackRequiresQueryParameters(t *testing.T) {
	_, err := RunStack(context.Background(), StackConfig{Target: "http://127.0.0.1:1/"})
	if err == nil {
		t.Fatal("expected error for target without query parameters")
	}
}

func TestRunStackRejectsBudgetTooSmall(t *testing.T) {
	server := newSQLiLab()
	defer server.Close()
	if _, err := RunStack(context.Background(), StackConfig{Target: server.URL + "/?id=1", RequestBudget: 10}); err == nil {
		t.Fatal("expected error for budget below the minimum")
	}
}

func TestRunStackRejectsNegativeConcurrency(t *testing.T) {
	server := newSQLiLab()
	defer server.Close()
	if _, err := RunStack(context.Background(), StackConfig{Target: server.URL + "/?id=1", RequestBudget: 60, Concurrency: -1}); err == nil {
		t.Fatal("expected error for negative concurrency")
	}
}

func TestRunStackBooleanBlindFallback(t *testing.T) {
	server := httptest.NewServer(newBlindHandler())
	defer server.Close()

	report, err := RunStack(context.Background(), StackConfig{Target: server.URL + "/?id=1", RequestBudget: 240, PreviewRows: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Parameters) != 1 || !report.Parameters[0].Injectable {
		t.Fatalf("expected one injectable parameter, got %+v", report.Parameters)
	}
	if p := report.Parameters[0]; len(p.DisplayColumns) != 0 {
		t.Fatalf("expected no display columns on a blind-only target, got %v", p.DisplayColumns)
	}
	if len(report.Databases) != 1 || report.Databases[0].Name != "appdb" {
		t.Fatalf("expected boolean-blind inferred database appdb, got %+v", report.Databases)
	}
}

func TestRunStackNumericInjection(t *testing.T) {
	server := newSQLiLabNumeric()
	defer server.Close()

	report, err := RunStack(context.Background(), StackConfig{Target: server.URL + "/?id=1", RequestBudget: 120, PreviewRows: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Parameters) != 1 || !report.Parameters[0].Injectable {
		t.Fatalf("expected one injectable parameter, got %+v", report.Parameters)
	}
	if p := report.Parameters[0]; p.InjectionType != "numeric" {
		t.Fatalf("expected numeric injection, got %q", p.InjectionType)
	}
	db := findDatabase(report, "appdb")
	if db == nil || len(db.Tables) != 1 || db.Tables[0].Name != "users" {
		t.Fatalf("expected appdb.users, got %+v", report.Databases)
	}
}

func TestRunStackParenInjection(t *testing.T) {
	server := newSQLiLabParen()
	defer server.Close()

	report, err := RunStack(context.Background(), StackConfig{Target: server.URL + "/?id=1", RequestBudget: 120, PreviewRows: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Parameters) != 1 || !report.Parameters[0].Injectable {
		t.Fatalf("expected one injectable parameter, got %+v", report.Parameters)
	}
	if p := report.Parameters[0]; p.InjectionType != "string (single-quote + paren)" {
		t.Fatalf("expected parenthesized single-quote injection, got %q", p.InjectionType)
	}
	db := findDatabase(report, "appdb")
	if db == nil || len(db.Tables) != 1 || db.Tables[0].Name != "users" {
		t.Fatalf("expected appdb.users, got %+v", report.Databases)
	}
}

func TestDynamicPageNoFalsePositive(t *testing.T) {
	// The page returns a different body on every request but never a database
	// error. The detection-only auditor must suppress body-length findings.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "dynamic content %s", r.URL.Query().Get("id"))
	}))
	defer server.Close()

	report, err := Run(context.Background(), Config{Target: server.URL + "/?id=1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("dynamic page should not produce findings, got %+v", report.Findings)
	}
}

func TestTargetIsRedactedAndCookieExcluded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	cookie := "session=secret-token-value"
	report, err := Run(context.Background(), Config{Target: server.URL + "/?id=1", Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(report.Target, "id=1") {
		t.Fatalf("target query values should be redacted, got %s", report.Target)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-token-value") {
		t.Fatalf("cookie must never appear in the report")
	}
}
