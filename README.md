# attested-tls-demo

**Bind attestation evidence to the TLS channel — or a relay attacker will thank you.**

A working Go demo of the core idea behind *attested TLS*: a server proves "I am the expected workload, on a patched platform" with attestation evidence, **and** the evidence is cryptographically bound to the client's own TLS session. A relay attacker replaying genuine evidence is detected; a client that skips the binding check is fooled.

## Why this exists

Verifying a quote is only half of attestation. The other half is *composition*: the evidence must be tied to the channel you are actually using, or a man-in-the-middle can relay someone else's good evidence and ride your trust. This failure class is live research: at Linux Plumbers Conference (Oct 2026), the TU Dresden / CCC Attestation SIG team presented CVEs against *early attestation* — attestation evidence delivered inside the TLS handshake — in IETF attested-TLS drafts, and proposed a new IRTF research group on confidential AI. The drafts are vulnerable for the same reason this demo's `--naive` mode is: genuine evidence, checked correctly, bound to nothing.

This project makes that abstract failure concrete and runnable.

## Architecture

```
 ┌──────────┐  1. TLS handshake (tls-unique ──┐   ┌──────────┐
 │  client  │─────────────────────────────────┘   │  server  │
 │(relying  │  2. GET /attest                    │ (attested │
 │ party)   │  3. quote{claims, REPORT_DATA=     │ workload) │
 │          │     HKDF(tls-unique, "attest")} ──▶ │          │
 │          │  4. verify sig + policy +           │          │
 │          │     REPORT_DATA == HKDF(my tls-     │          │
 │          │     unique)  ◀── THE BINDING CHECK  │          │
 │          │  5. POST /secret + proof=           │          │
 │          │     HKDF(tls-unique, "secret-proof")│          │
 │          │  6. server recomputes proof from    │          │
 │          │     ITS view of tls-unique ──▶ 200  │          │
 └──────────┘                                    └──────────┘

 attacker (cmd/relay):
 ┌──────────┐  TLS (relay CA)   ┌─────────┐  TLS (server CA)  ┌──────────┐
 │  victim  │ ◀───────────────▶ │  relay  │ ◀───────────────▶ │  server  │
 └──────────┘  victim trusts    └─────────┘  relay is a legit  └──────────┘
               relay's cert      forwards    attested client
               (compromised /     genuine     of the server
               misissued CA)      quote
```

The binding primitive is RFC 5929 `tls-unique`: identical on both endpoints of a session, different across sessions. The attester seals `HKDF(tls-unique)` into the quote's `REPORT_DATA`; the verifier recomputes it from its own session. A relayed quote carries the *attacker's* session binding, so the check fails.

## Quickstart

```bash
# terminal 1 — the attested workload
go run ./cmd/server --ca-out /tmp/attdemo/ca.pem

# terminal 2 — the honest client, direct connection
go run ./cmd/client --ca /tmp/attdemo/ca.pem --payload "record-123"
```

Expected output (verified 2026-10-05):

```
✅ attested: mrenclave=deadbeefcafef00d… mrsigner=0011223344556677… tcb=7
🔑 secret received: the-secret-only-attested-clients-get
📤 payload delivered over the attested channel
```

### The attack demo

```bash
# terminal 1 — server (as above)
go run ./cmd/server --ca-out /tmp/attdemo/ca.pem

# terminal 2 — the relay adversary (victim will trust ITS ca)
go run ./cmd/relay --upstream-ca /tmp/attdemo/ca.pem --ca-out /tmp/attdemo/relay-ca.pem

# terminal 3 — naive client: verifies signature + policy, skips binding
go run ./cmd/client --ca /tmp/attdemo/relay-ca.pem \
  --server https://127.0.0.1:9443 --naive --payload "ssn=123-45-6789"
```

The naive client prints ✅ attested, receives the secret, and delivers the payload — while the relay logs:

```
relay: INTERCEPTED sensitive payload: {"payload":"ssn=123-45-6789"}
```

Now the same victim with the binding check on (the default):

```bash
go run ./cmd/client --ca /tmp/attdemo/relay-ca.pem \
  --server https://127.0.0.1:9443 --payload "ssn=123-45-6789"
```

```
❌ attestation FAILED: RELAY DETECTED: genuine quote, but its REPORT_DATA
is bound to a different TLS session — refusing to trust this channel
```

Nothing sensitive is ever sent. The evidence was genuine; the *session* wasn't.

## API reference

| Package | Responsibility |
|---|---|
| `pkg/quote` | Mock TEE quote: `Claims` (measurements, TCB, `ReportData`, nonce), `Sign`/`Verify` (HMAC-SHA256 stands in for the quoting-enclave signature) |
| `pkg/binding` | Channel binding: `FromConnState` (RFC 5929 tls-unique), `ReportData`/`Proof` (HKDF-SHA256, stdlib-only RFC 5869 impl), `Check` (constant-time) |
| `pkg/policy` | Trust-policy appraisal: measurement/signer allow-lists, min TCB, quote freshness, and the `ExpectedReportData` binding rule |
| `internal/server` | Attested workload: `GET /attest` (session-bound quote), `POST /secret` (binding-proof-gated), `POST /data` |
| `internal/client` | Relying party: fetch → verify → bind → appraise → secret → payload; `Naive` mode skips binding |
| `internal/relay` | Demo adversary: own legitimate attested session upstream, replays genuine evidence downstream |
| `internal/certs` | Throwaway test PKI (self-signed CA + server certs, stdlib only) |

Tests: `go test ./...` — unit tests per package plus `tests/` integration tests proving all three scenarios (direct success, naive-fooled, bound-detects).

## What this demonstrates (interview talking points)

- **Attestation is a composition problem.** Signature verification and policy appraisal are necessary but not sufficient; evidence must be bound to the channel (this is the exact class of flaw in the early-attestation CVEs presented at Linux Plumbers 2026).
- **Channel bindings, concretely.** RFC 5929 `tls-unique` gives both endpoints the same session identifier for free; sealing `HKDF(tls-unique)` into `REPORT_DATA` is how real attested-TLS designs (and Intel's own quote flow) tie evidence to a session.
- **Adversary thinking.** The relay in this demo is *not* breaking crypto — it holds a perfectly legitimate attested session with the server. The vulnerability is purely in what the victim *fails to check*. Threat modeling > primitives.
- **Defense in depth, layered.** Even with binding, the server independently re-verifies a session proof before releasing secrets (`POST /secret`), so a stolen quote alone buys nothing.

## Limitations / how I'd productionize it

- **Mock quotes.** Real deployments use hardware quotes (SGX/TDX) verified against Intel PCS collateral, with TCB evaluation and revocation — the `pkg/quote` HMAC stands in for all of that deliberately.
- **Demo PKI.** The quoting key is compiled in (`internal/demo`, labeled DEMO ONLY); production needs a real trust root for verifier keys and proper CA management for the TLS layer.
- **TLS 1.2 pinned.** `tls-unique` semantics are cleanest on TLS 1.2; on TLS 1.3 the equivalent is the RFC 8446 exporter — the derivation would move to `tls.ConnectionState` exporter bindings.
- **No freshness protocol.** Nonces are random per quote; a production verifier would drive a challenge-response (verifier-supplied nonce in `REPORT_DATA` alongside the binding).
- **Single workload identity.** A real appraisal service (à la Intel Trust Authority) evaluates policy per tenant with versioned policies — see my [attestation-policy-gateway](https://github.com/PeaceXXX/attestation-policy-gateway) for that half.

## Clean-room statement

Built from public concepts and general engineering only: TLS channel bindings (RFC 5929), HKDF (RFC 5869), and the publicly documented attested-TLS/early-attestation research discourse. No Intel-internal code, APIs, or non-public details are used or implied.

## License

MIT — see [LICENSE](LICENSE).
