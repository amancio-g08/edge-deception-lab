# Edge Deception Lab

![ci](https://github.com/amancio-g08/edge-deception-lab/actions/workflows/ci.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-4A4A55?style=flat-square)

[Português](README.md) · English

A honeypot that classifies whoever hits it by behaviour, not by what the client claims
to be.

I work with Akamai: WAF tuning, bot exceptions, Site Shield, edge-to-origin
troubleshooting. The console shows what the platform decided. It doesn't show why, or
where it gets things wrong. I built this to understand the mechanism from the outside.

What came out is a sensor that serves a fake application, captures everything that
reaches it, and produces an explained verdict for every request.

![Dashboard](docs/dashboard.png)

## The idea

Every honeypot project I looked at answers one question: is this a bot? That doesn't
help much, because the answer is almost always yes.

There are two separate questions worth asking.

The first is whether anyone is driving. You can see it in the client stack: which
headers came, in what order, whether `Sec-Fetch-*` is there, whether Client Hints are.
Browsers are very predictable about this. curl, requests and most scanners aren't, and
that gap survives a spoofed User-Agent.

The second is what the client wants. That only shows up in behaviour over time: how
many distinct paths it swept, whether it sent exploit-shaped payloads, whether it kept
rotating usernames at the login.

An uptime monitor scores high on the first question and zero on the second. Credential
stuffing out of a residential proxy pool slips through the first and is an attack on
the second. Merging both into one score creates exactly the false positive that gets a
customer asking for the whole policy back on alert-only.

So there are two scores. The intent one decides the verdict.

### Verdicts

| Verdict | What it means | What I'd do in production |
|---------|---------------|---------------------------|
| `verified_crawler` | Identity proven by confirmed rDNS | Allowlist, never challenge |
| `vuln_scanner` | Sweeping for artifacts or sending exploit payloads | Block |
| `credential_attack` | Login attempts with rotating usernames | Block and rate limit |
| `content_scraper` | Systematic content iteration, or a fake crawler | Challenge or tarpit |
| `recon_probe` | Touching admin surface, no clear pattern yet | Monitor |
| `unclassified_automation` | Automated, intent unreadable | Alert only |
| `likely_human` | Coherent browser fingerprint, low velocity | Allow |

`unclassified_automation` doesn't compete with the others. It's a waiting queue. Moving
a rule out of alert and into block needs evidence, and that's where the evidence piles
up.

### Every verdict ships its evidence

No score comes out without the list of signals behind it. It's the bare minimum for
answering a ticket asking why someone's integration got hit.

```json
{
  "verdict": "vuln_scanner",
  "confidence": 0.83,
  "automation_score": 7.0,
  "human_score": 0.0,
  "signals": [
    {"name": "sensitive_artifact_request", "weight": 4.0, "detail": "/.env"},
    {"name": "path_enumeration",           "weight": 4.0, "detail": "70 paths"},
    {"name": "high_404_ratio",             "weight": 2.5, "detail": "95%"},
    {"name": "automation_user_agent",      "weight": 3.5, "detail": "nikto"}
  ]
}
```

## Architecture

```
                    ┌──────────────────────────────────────────┐
   internet ───────▶│  edge (nginx)                            │
                    │  · sets X-Edge-Client-IP, no exceptions  │
                    │  · rate limits                           │
                    │  · returns 404 for /_edl/*               │
                    └───────────────────┬──────────────────────┘
                                        │
                    ┌───────────────────▼──────────────────────┐
                    │  sensor (FastAPI)                        │
                    │                                          │
                    │  decoys ──▶ inert static responses       │
                    │  fingerprint ──▶ client-stack signals    │
                    │  enrich ──▶ confirmed rDNS               │
                    │  storage ──▶ velocity aggregates         │
                    │  classifier ──▶ explainable verdict      │
                    └───────────────────┬──────────────────────┘
                                        │
                              SQLite (WAL) ──▶ /_edl/dashboard
```

nginx isn't decoration. It's what establishes the source IP the sensor trusts,
overwriting the header without asking. A honeypot that believes the `X-Forwarded-For`
it got off the wire has attacker-controlled data inside its own aggregates.

Design notes and the sensor's threat model are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Running it

```bash
git clone https://github.com/amancio-g08/edge-deception-lab.git
cd edge-deception-lab

cp .env.example .env          # change EDL_CREDENTIAL_SALT
docker compose up --build -d

python tools/simulate_traffic.py --rounds 20 --simulate-edge
```

Dashboard at `http://127.0.0.1:8081/_edl/dashboard`.

`--simulate-edge` gives each profile a synthetic source IP from the RFC 5737
documentation ranges. Without it everyone comes from the same address and the velocity
aggregates collapse into a single client.

### Without Docker

Only nginx needs a container. The rest runs on Python:

```bash
pip install -r honeypot/requirements.txt
EDL_DB_PATH=./data/events.db python -m uvicorn honeypot.app.main:app --port 8080
python tools/simulate_traffic.py --target http://127.0.0.1:8080 --rounds 20 --simulate-edge
pytest -q
```

Dashboard at `http://127.0.0.1:8080/_edl/dashboard`. Running it this way means no edge
in front, so `X-Edge-Client-IP` isn't overwritten. Fine for local work, not fine for
anything exposed.

### Configuration

| Variable | Default | What it does |
|----------|---------|--------------|
| `EDL_DB_PATH` | `/data/events.db` | Where the SQLite file goes |
| `EDL_CREDENTIAL_SALT` | `edge-deception-lab` | Salt for every stored digest. Change it |
| `EDL_VERIFY_BOT_RDNS` | `true` | Confirmed rDNS for crawler verification |
| `EDL_VELOCITY_WINDOW` | `300` | Velocity window, in seconds |
| `EDL_STORE_IP_RAW` | `true` | `false` keeps only the hashed IP |
| `EDL_PUBLIC_BIND` | `127.0.0.1` | Edge bind address. Only change it on purpose |

## Care

The sensor exists to take hits, so it has to be annoying to attack.

There's nothing executable in there. Every decoy response is a static string: no
templating of user input, no path-driven file reads, no deserialization. The login
always fails, because a honeypot that lets someone in becomes an attacker's foothold on
a machine you own.

Passwords never get stored in clear text. Passwords, tokens, cookies and
`Authorization` headers become salted SHA-256 digests before they reach the database.
Repeat attempts still correlate, and I never end up holding a usable third-party
credential. It's in `tests/test_redact.py`, and if that breaks the lab isn't safe to
run.

The client never finds out it was classified either. The verdict doesn't show up in a
header, a status code or a timing difference. Anyone who notices they're being profiled
changes behaviour, and then the sensor stops measuring anything.

> Before putting this on the internet: isolated host with no lateral access to anything
> that matters, a unique `EDL_CREDENTIAL_SALT`, and read your provider's abuse policy.
> Capturing traffic somebody sent at your own infrastructure is one thing. Where you
> host it and what you do with the data afterwards is on you, GDPR included, since a
> source IP is personal data. `EDL_STORE_IP_RAW=false` keeps only the hash.

## What doesn't work well yet

Velocity is keyed by IP, so CGNAT and corporate egress mix people together. I found
this running the simulator locally, where every profile comes from `127.0.0.1`: a `GET
/admin` came back as `credential_attack`, because username rotation from a different
profile had polluted the aggregate. There's a gate now that only counts username
rotation on an actual authentication attempt, plus a test pinning it in both
directions. The real fix is fingerprint-based identity, which is on the roadmap.

There's no TLS fingerprinting. JA4 lives below the reverse proxy and is the strongest
automation signal there is. Until it's in, a client that reproduces browser headers
properly passes as a browser.

The weights were set by eye. They come from reasoning about how these clients behave,
validated against synthetic profiles and a false-positive suite. They don't come from a
labelled corpus.

rDNS is best effort. Lookups are cached with a short timeout, and a resolver failure
downgrades a legitimate crawler to unverified instead of failing open.

## Tests

```
33 passed
```

| File | What it protects |
|------|------------------|
| `test_classifier.py` | Verdicts for known-hostile behaviour |
| `test_false_positives.py` | Legitimate clients a greedy rule would flag |
| `test_redact.py` | That no credential reaches the database in clear text |
| `test_capture.py` | End-to-end capture, and that profiling stays invisible |

## Roadmap

One branch per capability. What's coming, and why, is in [`ROADMAP.md`](ROADMAP.md).

## License

MIT.
