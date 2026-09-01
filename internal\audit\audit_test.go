package audit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectsErrorSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "1'" {
			http.Error(w, "You have an error in your SQL syntax", 500)
			return
		}
		fmt.Fprint(w, "normal page")
	}))
	defer server.Close()
	report, err := Run(context.Background(), Config{Target: server.URL + "/?id=1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Confidence != "high" {
		t.Fatalf("unexpected report: %+v", report)
	}
}
func TestSafeEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "same page") }))
	defer server.Close()
	report, err := Run(context.Background(), Config{Target: server.URL + "/?id=1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("unexpected finding: %+v", report)
	}
}
