# Roadmap

One branch per capability, merged with `--no-ff` so the history keeps the shape
of the work. Each phase is independently useful — nothing here is a prerequisite
for running what already exists.

Branch naming: `feat/<capability>`, `fix/<defect>`, `docs/<subject>`,
`chore/<task>`.

---

## Shipped

### Phase 1 — sensor core
`feat/decoy-surface` · `feat/fingerprinting` · `feat/classifier` ·
`feat/dashboard` · `feat/edge-layer`

Inert decoy surface, request fingerprinting, forward-confirmed rDNS crawler
verification, two-axis behavioural classifier with explainable signals, SQLite
persistence, analysis dashboard, nginx edge layer, Docker Compose, 33 tests.

---

## Planned

### Phase 2 — `feat/ja4-fingerprinting`
**Why:** TLS fingerprinting is the strongest automation signal available, and its
absence is the biggest current blind spot. A client that reproduces browser
headers perfectly is invisible to header-based detection; its TLS ClientHello
still is not.

**Approach:** terminate TLS at a Go or Rust listener that computes JA4/JA4S and
forwards the hash to the sensor as a header, since Python cannot see the
ClientHello through the socket. Store the hash, correlate it against the header
order hash, and flag disagreement between the two — a browser TLS fingerprint
paired with a scripted header set is a contradiction that survives spoofing.

**Done when:** a `curl` request and a real Chrome request to the same path carry
different JA4 hashes in the event record, and the mismatch signal fires.

---

### Phase 3 — `feat/fingerprint-identity`
**Why:** velocity currently keys on source IP, so one CGNAT address mixes many
users into one profile. This is the root cause of the shared-IP false positive
that `test_false_positives.py` currently mitigates rather than solves.

**Approach:** derive a composite client identity from header order hash + JA4 +
Accept-Language + declared platform. Key velocity aggregates on that identity
instead of the address. Keep the IP as a secondary dimension for reporting.

**Done when:** two distinct synthetic clients behind the same source IP produce
independent velocity contexts.

---

### Phase 4 — `feat/asn-enrichment`
**Why:** the hosting provider behind an address is a strong prior. Residential
ranges, datacenter ASNs and known proxy pools each imply a different baseline,
and "browser fingerprint originating from a cloud ASN" is a classic
contradiction.

**Approach:** offline MaxMind GeoLite2 ASN database, loaded at startup, no
runtime API calls. Add an `asn_context` signal and surface top ASNs on the
dashboard.

**Done when:** events carry ASN and country, and a datacenter-origin browser
fingerprint raises its automation score.

---

### Phase 5 — `feat/waf-simulation`
**Why:** this is the bridge back to the day job. Once traffic is classified, the
obvious next question is what a real policy would have done with it — and how
many legitimate requests a given ruleset would have caught.

**Approach:** evaluate captured requests against an OWASP CRS-style rule subset
at each paranoia level, and report detection coverage against false positives on
the same corpus. Produce the alert-to-block readiness view that a tuning
exercise actually needs.

**Done when:** a report answers "at paranoia level 2, this policy blocks N
hostile requests and M legitimate ones" from real captured traffic.

---

### Phase 6 — `feat/reporting`
**Why:** the output of an analysis is a document someone acts on, not a
dashboard someone glances at.

**Approach:** scheduled report generation — top attacking sources, campaign
clustering by fingerprint, new signals seen since the last run, recommended rule
changes with the evidence attached. Markdown and PDF.

**Done when:** `make report` produces a document that could be sent to a customer
without editing.

---

### Phase 7 — `feat/multi-sensor`
**Why:** one sensor sees one vantage point. Correlating the same fingerprint
across regions distinguishes a targeted campaign from internet background
radiation.

**Approach:** sensors push events to a collector; identity correlation across
sensors; first-seen/last-seen per fingerprint.

**Done when:** the same synthetic client hitting two sensors is reported as one
actor.

---

## Not planned

- **Active response.** No blocking, no tarpitting, no counter-scanning. A sensor
  that acts on traffic stops being an observation instrument and starts being a
  participant, with the legal exposure that implies.
- **Real vulnerable software.** No deliberately outdated CMS, no exploitable
  services. The decoy surface stays inert — see the safety section of the README.
