# Contributing

1. Create a focused branch.
2. Run `gofmt -w .`, `go test -buildvcs=false ./...`, and `go vet -buildvcs=false ./...`.
3. Preserve request budgets, redaction, TLS verification, localhost binding, and explicit authorization checks.
4. Include local `httptest` coverage for detection and stack changes.

## Scope

Supported and welcome:

- Bounded, authorization-gated schema enumeration and data preview within the request budget.
- Heuristic detection improvements that reduce false positives.
- MySQL-compatible targets and additional database error signatures.

Out of scope:

- Unbounded data export, credential theft, authentication bypass, destructive payloads, timing attacks, and evasion features.
- Any feature that removes the authorization confirmation or request limits.
