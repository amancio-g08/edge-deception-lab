# Architecture

## Request lifecycle

```
1. edge (nginx)
   ├─ overwrite X-Edge-Client-IP with $remote_addr   ← client-supplied value discarded
   ├─ limit_req (30 r/s, burst 60)
   └─ return 404 for /_edl/*                          ← management surface is not public

2. sensor (FastAPI, catch-all route)
   ├─ capture     raw body (truncated), headers, header ORDER
   ├─ enrich      forward-confirmed rDNS (cached, time-bounded)
   ├─ fingerprint client-stack signals
   ├─ decoy       static response lookup (pure, no I/O)
   ├─ velocity    sliding-window aggregates for this source
   ├─ classify    weighted scoring → verdict + signals
   ├─ redact      credentials → salted digest
   └─ persist     SQLite (WAL)

3. response
   └─ static decoy body, Server: nginx, no verdict leaked
```

Classification happens **before** the response is sent but never influences it.
That ordering is deliberate: a client that can infer its own classification —
from a header, a status code, or a measurable timing difference — will adapt, and
the sensor stops measuring anything real.

## Why these components

**nginx as the edge layer.** Not decoration. It establishes the one property the
whole capture depends on: the source address the sensor trusts is set by
infrastructure the client cannot influence. `proxy_set_header X-Edge-Client-IP
$remote_addr` overwrites whatever arrived under that name. A honeypot that trusts
`X-Forwarded-For` from the wire has attacker-controlled source data in its
dataset, which invalidates every velocity aggregate built on it.

**SQLite with WAL.** The lab has to be clonable and runnable with one command.
WAL keeps dashboard reads from blocking capture writes, and the whole dataset is
one file that can be copied off the host for offline analysis. A single writer is
sufficient — the sensor is not the bottleneck under any traffic a honeypot
receives.

**FastAPI with docs disabled.** `docs_url`, `redoc_url` and `openapi_url` are all
`None`. A decoy surface that advertises FastAPI is not imitating the application
it claims to be, and the framework banner is one of the first things a scanner
records.

## Data model

One row per request. Denormalized on purpose: the analysis queries are
aggregations over a single table, and a star schema would buy nothing at this
scale while making the SQL harder to read in a repository whose point is being
readable.

Indexes cover the four access patterns: time range, source + time (velocity),
verdict (breakdown), path (top targets).

Two derived columns carry most of the analytical weight:

- `header_order_hash` — digest of the header names in arrival order. A property
  of the HTTP client implementation, not of the request content. Two requests
  with the same hash very likely came from the same stack even across different
  User-Agent strings.
- `src_ip_hash` — salted digest of the source address, always populated. The raw
  address is optional (`EDL_STORE_IP_RAW=false`), so the sensor can run without
  retaining personal data while keeping every correlation intact.

## Classifier internals

Signals are `(name, weight, verdict, detail)` tuples produced by four
independent extractors:

| Extractor | Reads | Produces |
|-----------|-------|----------|
| `_path_signals` | method, path, query | intent evidence: artifacts, exploit shapes, login posts |
| `_fingerprint_signals` | client stack | automation evidence, crawler verification |
| `_velocity_signals` | sliding window | enumeration, rotation, volume |
| `_human_signals` | client stack + window | evidence *against* automation |

Weights sum per verdict. Then:

1. **A verified crawler short-circuits.** Once identity is proven by
   forward-confirmed rDNS, no behavioural score overrides it. This mirrors
   allowlist semantics in a production bot manager — a verified Googlebot
   crawling aggressively is still Googlebot.
2. **Intent verdicts are ranked against each other**, excluding
   `unclassified_automation`. Automation is a separate axis, not a competitor;
   letting a noisy client fingerprint outvote an unambiguous attack pattern is
   the false negative that matters.
3. **Confidence blends three terms:** margin over the runner-up intent, absolute
   magnitude of evidence, and a corroboration bonus when the client also looks
   automated. A 10-vs-9 split must not report the same certainty as a 10-vs-0
   split.
4. **Fallbacks in order:** automated but illegible → `unclassified_automation`;
   otherwise → `likely_human`.

### The gate that took a test to find

Username-rotation signals fire only when the request being classified is itself
an authentication attempt. Without that gate, one credential-stuffing run behind
a corporate egress IP recolours every unrelated request from the same address —
because velocity aggregates key on the IP, and the IP is shared.

This is not hypothetical: it appeared in the first local run, where every
synthetic profile shared `127.0.0.1` and a `GET /admin` came back labelled
`credential_attack`. It is pinned by
`test_shared_ip_credential_run_does_not_taint_unrelated_requests`, with the
inverse case pinned beside it so the fix cannot silently disarm the detection it
protects.

## Threat model for the sensor itself

The sensor is deliberately exposed to hostile traffic, so it is treated as
untrusted-adjacent infrastructure.

| Threat | Mitigation |
|--------|-----------|
| RCE through the decoy surface | No dynamic evaluation anywhere. `decoys.resolve()` is a pure dict lookup — no filesystem access, no templating of user input, no deserialization |
| Sensor used as an upload target | `client_max_body_size 64k` at the edge; body truncated to `EDL_MAX_BODY_BYTES` before storage |
| Storage exhaustion | Rate limiting at the edge; body truncation; SQLite is the only writable path |
| Credential liability | Salted digests only, enforced by `tests/test_redact.py` |
| Attacker detects the honeypot | Framework banners disabled, verdict never leaked, static `Server: nginx` |
| Container compromise → lateral movement | Non-root UID 10001, read-only application code, only `/data` writable, dashboard bound to loopback |
| Poisoned source data | Trusted IP header set unconditionally at the edge |

## Deliberate omissions

**No active response.** The sensor never blocks, tarpits, or probes back. An
observation instrument that acts on traffic becomes a participant, with the legal
exposure that implies.

**No real vulnerable software.** No outdated CMS, no exploitable services. The
value is in the classifier, and a genuinely exploitable host is an attacker
foothold on infrastructure you own.

**No machine learning.** With hand-tuned weights, every verdict is traceable to
the rule that produced it. A model would need a labelled corpus this lab does not
have, and would trade the explainability that makes the output defensible for
accuracy it cannot yet demonstrate.
