package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fetchToken(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	resp, err := http.Get(srv.URL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var cfg struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Token == "" {
		t.Fatal("expected a non-empty session token")
	}
	return cfg.Token
}

func postStack(t *testing.T, srv *httptest.Server, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/stack", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Auditor-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestStackRequiresSessionToken(t *testing.T) {
	srv := httptest.NewServer(newHandler())
	defer srv.Close()
	resp := postStack(t, srv, "", `{"target":"http://127.0.0.1:1/?id=1"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without token, got %d", resp.StatusCode)
	}
}

func TestStackRejectsMissingAuthorization(t *testing.T) {
	srv := httptest.NewServer(newHandler())
	defer srv.Close()
	token := fetchToken(t, srv)
	resp := postStack(t, srv, token, `{"target":"http://127.0.0.1:1/?id=1","confirmation":"nope"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 without valid confirmation, got %d", resp.StatusCode)
	}
}

func TestValidConfirmationAcceptsBothPhrases(t *testing.T) {
	if !validConfirmation("我已获得授权") {
		t.Fatal("Chinese confirmation phrase should be accepted")
	}
	if !validConfirmation("I HAVE AUTHORIZATION") {
		t.Fatal("English confirmation phrase should be accepted")
	}
	if validConfirmation("yes") {
		t.Fatal("arbitrary text must be rejected")
	}
}

func readWeb(t *testing.T, name string) string {
	t.Helper()
	data, err := webFiles.ReadFile("web/" + name)
	if err != nil {
		t.Fatalf("reading web/%s: %v", name, err)
	}
	return string(data)
}

func TestI18nStaticCheck(t *testing.T) {
	i18n := readWeb(t, "i18n.js")
	app := readWeb(t, "app.js")
	html := readWeb(t, "index.html")

	// Both languages must be present with matching required translations.
	for _, want := range []string{"zh: {", "en: {", "我已获得授权", "I HAVE AUTHORIZATION", "参数检测", "Parameter detection", "数据预览", "Data preview", "部分完成", "Partial"} {
		if !strings.Contains(i18n, want) {
			t.Fatalf("i18n.js missing %q", want)
		}
	}

	// Rendering must use safe DOM APIs, never innerHTML with user data.
	if strings.Contains(app, ".innerHTML") {
		t.Fatal("app.js must not use innerHTML")
	}
	if !strings.Contains(app, "textContent") {
		t.Fatal("app.js should render via textContent")
	}

	// Default locale must be Simplified Chinese.
	if !strings.Contains(html, `lang="zh-CN"`) {
		t.Fatal("index.html must default to zh-CN")
	}
}
