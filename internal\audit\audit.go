package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const MaxParameters = 5
const maxBody = 1 << 20

type Config struct {
	Target, Cookie string
	Delay          time.Duration
}
type Finding struct {
	Parameter  string `json:"parameter"`
	Confidence string `json:"confidence"`
	DBHint     string `json:"db_hint,omitempty"`
	Evidence   string `json:"evidence"`
}
type Report struct {
	Schema     string    `json:"schema"`
	Target     string    `json:"target"`
	Requests   int       `json:"requests"`
	DurationMS int64     `json:"duration_ms"`
	Findings   []Finding `json:"findings"`
	Notes      []string  `json:"notes"`
}
type sample struct {
	status, length int
	hash, body     string
}

var errorsByDB = map[string]*regexp.Regexp{
	"MySQL":      regexp.MustCompile(`(?i)(you have an error in your sql syntax|unknown column|the used select statements have a different number of columns|illegal mix of collations|unknown database|doesn't exist|warning.*mysql_|mysqli?_)`),
	"PostgreSQL": regexp.MustCompile(`(?i)(postgresql.*error|pg_query\(|unterminated quoted string)`),
	"SQL Server": regexp.MustCompile(`(?i)(unclosed quotation mark|sql server.*driver|microsoft ole db provider for sql server)`),
	"Oracle":     regexp.MustCompile(`(?i)(ORA-[0-9]{5}|quoted string not properly terminated)`),
	"SQLite":     regexp.MustCompile(`(?i)(sqlite.*error|sqlite3\.OperationalError|unrecognized token:)`),
}

func Run(ctx context.Context, cfg Config) (Report, error) {
	start := time.Now()
	parsed, err := url.Parse(strings.TrimSpace(cfg.Target))
	if err != nil || parsed.Hostname() == "" {
		return Report{}, errors.New("valid target URL is required")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return Report{}, errors.New("only http and https targets are supported")
	}
	params := parsed.Query()
	if len(params) == 0 {
		return Report{}, errors.New("target URL must contain query parameters")
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > MaxParameters {
		return Report{}, fmt.Errorf("at most %d parameters per audit", MaxParameters)
	}
	client, err := guardedClient(ctx, parsed)
	if err != nil {
		return Report{}, err
	}
	if cfg.Delay < 0 || cfg.Delay > 2*time.Second {
		return Report{}, errors.New("delay must be between 0 and 2 seconds")
	}
	report := Report{Schema: "sqli-auditor-report/1.0", Target: redact(parsed), Findings: []Finding{}, Notes: []string{"Detection only: no schema enumeration, data extraction, or time-delay probes."}}
	baseline, err := fetch(ctx, client, parsed, cfg.Cookie)
	report.Requests++
	if err != nil {
		return report, err
	}
	if err := sleep(ctx, cfg.Delay); err != nil {
		return report, err
	}
	baselineCheck, err := fetch(ctx, client, parsed, cfg.Cookie)
	report.Requests++
	if err != nil {
		return report, err
	}
	stableBaseline := baseline.hash == baselineCheck.hash && baseline.status == baselineCheck.status
	if !stableBaseline {
		report.Notes = append(report.Notes, "The baseline changed between requests; body-length-only findings were suppressed.")
	}
	for _, key := range keys {
		if err := sleep(ctx, cfg.Delay); err != nil {
			return report, err
		}
		probeURL := cloneURL(parsed)
		q := probeURL.Query()
		original := q.Get(key)
		q.Set(key, original+"'")
		probeURL.RawQuery = q.Encode()
		probe, fetchErr := fetch(ctx, client, probeURL, cfg.Cookie)
		report.Requests++
		if fetchErr != nil {
			continue
		}
		dbHint := ""
		for db, pattern := range errorsByDB {
			if pattern.MatchString(probe.body) && !pattern.MatchString(baseline.body) {
				dbHint = db
				break
			}
		}
		statusChanged := probe.status >= 500 && baseline.status < 500
		lengthDelta := abs(probe.length - baseline.length)
		materialDelta := lengthDelta > max(120, baseline.length/5)
		if dbHint != "" || statusChanged || (stableBaseline && materialDelta && probe.hash != baseline.hash) {
			confidence := "medium"
			evidence := fmt.Sprintf("response changed: HTTP %d→%d, body delta %d bytes", baseline.status, probe.status, lengthDelta)
			if dbHint != "" {
				confidence = "high"
				evidence = "a database error signature appeared only after a quote-boundary probe"
			}
			report.Findings = append(report.Findings, Finding{Parameter: key, Confidence: confidence, DBHint: dbHint, Evidence: evidence})
		}
	}
	report.DurationMS = time.Since(start).Milliseconds()
	return report, nil
}

func guardedClient(ctx context.Context, u *url.URL) (*http.Client, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("target did not resolve to an IP address")
	}
	var chosen net.IP
	for _, ip := range ips {
		if allowedIP(ip) {
			chosen = ip
			break
		}
	}
	if chosen == nil {
		return nil, errors.New("target resolves only to blocked link-local, multicast, or unspecified addresses")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(chosen.String(), port))
	}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxIdleConns: 32, MaxIdleConnsPerHost: 16, IdleConnTimeout: 60 * time.Second}
	return &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func allowedIP(ip net.IP) bool {
	return !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}
func fetch(ctx context.Context, client *http.Client, u *url.URL, cookie string) (sample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return sample{}, err
	}
	req.Header.Set("User-Agent", "SQLi-Auditor/1.0 authorized-security-test")
	if strings.TrimSpace(cookie) != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return sample{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return sample{}, err
	}
	if len(body) > maxBody {
		return sample{}, errors.New("response body exceeds 1 MiB limit")
	}
	sum := sha256.Sum256(body)
	return sample{status: resp.StatusCode, length: len(body), hash: hex.EncodeToString(sum[:]), body: string(body)}, nil
}
func redact(u *url.URL) string {
	v := cloneURL(u)
	q := v.Query()
	for key := range q {
		q.Set(key, "REDACTED")
	}
	v.RawQuery = q.Encode()
	return v.String()
}
func cloneURL(u *url.URL) *url.URL { v := *u; return &v }
func sleep(ctx context.Context, d time.Duration) error {
	if d == 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
