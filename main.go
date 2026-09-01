package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/C-8H11N/sqli-auditor/internal/audit"
)

//go:embed web/*
var webFiles embed.FS

type request struct {
	Target        string `json:"target"`
	Cookie        string `json:"cookie"`
	Confirmation  string `json:"confirmation"`
	DelayMS       int    `json:"delay_ms"`
	RequestBudget int    `json:"request_budget"`
	PreviewRows   int    `json:"preview_rows"`
	Concurrency   int    `json:"concurrency"`
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "audit" || os.Args[1] == "stack") {
		runCLI(os.Args[1], os.Args[2:])
		return
	}
	addr := flag.String("listen", "127.0.0.1:8812", "local web address")
	flag.Parse()
	server := &http.Server{Addr: *addr, Handler: newHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 6 * time.Minute, WriteTimeout: 6 * time.Minute, IdleTimeout: 90 * time.Second}
	log.Printf("SQLi Auditor is ready at http://%s", *addr)
	log.Fatal(server.ListenAndServe())
}

// newHandler builds the full HTTP handler with an ephemeral session token.
// It is exported for use by the API tests.
func newHandler() http.Handler {
	token := randomToken()
	sub, _ := fs.Sub(webFiles, "web")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"token":                  token,
			"max_parameters":         audit.MaxParameters,
			"default_request_budget": audit.DefaultRequestBudget,
			"max_request_budget":     audit.MaxRequestBudget,
			"max_preview_rows":       audit.MaxPreviewRows,
			"default_concurrency":    audit.DefaultConcurrency,
			"max_concurrency":        audit.MaxConcurrency,
		})
	})
	mux.HandleFunc("POST /api/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auditor-Token") != token || !sameOrigin(r) {
			writeJSON(w, 403, map[string]string{"error": "local session validation failed"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		var req request
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid JSON request"})
			return
		}
		if !validConfirmation(req.Confirmation) {
			writeJSON(w, 400, map[string]string{"error": "type the authorization confirmation exactly"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		report, err := audit.Run(ctx, audit.Config{Target: req.Target, Cookie: req.Cookie, Delay: time.Duration(req.DelayMS) * time.Millisecond})
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, report)
	})
	mux.HandleFunc("POST /api/stack", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auditor-Token") != token || !sameOrigin(r) {
			writeJSON(w, 403, map[string]string{"error": "local session validation failed"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		var req request
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid JSON request"})
			return
		}
		if !validConfirmation(req.Confirmation) {
			writeJSON(w, 400, map[string]string{"error": "type the authorization confirmation exactly"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		report, err := audit.RunStack(ctx, audit.StackConfig{Target: req.Target, Cookie: req.Cookie, Delay: time.Duration(req.DelayMS) * time.Millisecond, RequestBudget: req.RequestBudget, PreviewRows: req.PreviewRows, Concurrency: req.Concurrency})
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, report)
	})
	return headers(mux)
}

func runCLI(mode string, args []string) {
	set := flag.NewFlagSet(mode, flag.ExitOnError)
	target := set.String("target", "", "authorized URL with query parameters")
	delay := set.Int("delay", 150, "delay between probes in milliseconds")
	budget := set.Int("budget", audit.DefaultRequestBudget, "full-stack request budget")
	rows := set.Int("rows", 3, "full-stack preview rows per table")
	conc := set.Int("conc", audit.DefaultConcurrency, "full-stack enumeration concurrency")
	authorized := set.Bool("authorized", false, "confirm authorization")
	_ = set.Parse(args)
	if !*authorized {
		log.Fatal("refusing to audit: pass -authorized after confirming permission")
	}
	var report any
	var err error
	if mode == "stack" {
		report, err = audit.RunStack(context.Background(), audit.StackConfig{Target: *target, Delay: time.Duration(*delay) * time.Millisecond, RequestBudget: *budget, PreviewRows: *rows, Concurrency: *conc})
	} else {
		report, err = audit.Run(context.Background(), audit.Config{Target: *target, Delay: time.Duration(*delay) * time.Millisecond})
	}
	if err != nil {
		log.Fatal(err)
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	os.Stdout.Write(data)
}

func validConfirmation(value string) bool {
	return value == "I HAVE AUTHORIZATION" || value == "我已获得授权"
}
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin == "" || origin == "http://"+r.Host || origin == "https://"+r.Host
}
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
