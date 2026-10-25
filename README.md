# SentinalX

**AI-assisted endpoint detection and response for the investigation-first SOC.**

SentinalX is a portfolio-grade, small-scale EDR platform built to demonstrate how endpoint telemetry can become a reliable detection and investigation product—not just another antivirus dashboard.

> This repository is a self-contained product demo. It uses realistic, synthetic telemetry and an in-memory API so the core workflows can be run locally without cloud accounts, agents, or external services.

## Why this project exists

Most security tooling stops at “an alert fired.” SentinalX focuses on what happens next:

- Normalize process, file, network, and identity activity into a common event model.
- Combine deterministic rules with an independently evaluated behavioral anomaly score.
- Correlate weak signals into an attack chain with linked evidence and reliable timestamps.
- Give an AI investigation analyst enough context to produce an evidence-linked narrative.
- Turn confirmed investigations into draft detections, replay tests, and auditable learning.
- Recommend containment while keeping disruptive actions behind explicit human approval.

## Product surface

| Area | What is demonstrated |
| --- | --- |
| **Command center** | Signal velocity, event composition, prioritized signals, endpoint health |
| **Incident queue** | Correlated incidents with severity, confidence, endpoint, user, and summary |
| **Investigation workspace** | Attack-chain reconstruction, process lineage, entity graph inputs, evidence timeline |
| **Detection studio** | Rule and anomaly detections, confidence, coverage, false-positive counts, draft proposals |
| **Replay lab** | Recorded scenario replay against current detections and anomaly scoring |
| **Learning loop** | Confirm/benign analyst feedback captured as explicit labels |
| **Audit trail** | Response approvals, replay outcomes, and detection proposals |
| **Safe response** | Isolation, token revocation, and blocking recommendations require approval |

## Architecture

```text
┌──────────────────────┐       ┌──────────────────────────┐
│ Synthetic endpoints  │──────▶│ Normalized event layer   │
│ Sysmon / DNS / Net   │       │ reliable ISO timestamps  │
└──────────────────────┘       └─────────────┬────────────┘
                                             │
                         ┌───────────────────┴──────────────────┐
                         │                                      │
              ┌──────────▼──────────┐                ┌──────────▼──────────┐
              │ Rule detections     │                │ Anomaly scoring     │
              │ explainable logic   │                │ baseline deviation  │
              └──────────┬──────────┘                └──────────┬──────────┘
                         └───────────────────┬──────────────────┘
                                             │
                                  ┌──────────▼──────────┐
                                  │ Correlation engine  │
                                  │ incident + timeline │
                                  └──────────┬──────────┘
                                             │
       ┌─────────────────────────────────────┼─────────────────────────────────────┐
       │                                     │                                     │
┌──────▼──────┐                    ┌─────────▼─────────┐                   ┌───────▼───────┐
│ Analyst UI   │                    │ Replay / learning │                   │ Safe response │
│ investigation│                    │ rule proposals    │                   │ approval gate │
└──────────────┘                    └───────────────────┘                   └───────────────┘
```

### Backend

- `src/server.js` — dependency-free Node HTTP API and static file server.
- `src/platform.js` — domain model, synthetic telemetry, correlation data, anomaly score, replay engine, RBAC, audit, and proposal flows.
- API endpoints include `/api/dashboard`, `/api/events`, `/api/incidents`, `/api/detections`, `/api/replays`, `/api/audit`, incident feedback, detection proposals, and response approvals.

### Frontend

- `public/index.html` — application shell.
- `public/styles.css` — dark SOC interface with responsive behavior.
- `public/app.js` — API-backed navigation and interaction flows.

## Quick start

Requirements: Node.js 20+.

```bash
npm test
npm run check
npm start
```

Then open [http://localhost:4173](http://localhost:4173).

For a development loop with automatic server restart:

```bash
npm run dev
```

## Demo walkthrough

1. Open **Overview** and inspect the signal velocity, event composition, and prioritized signals.
2. Open **Incidents** and select `INC-2026-1042`.
3. Review the reconstructed chain: Word document → VBScript → encoded PowerShell → external TLS → cloud identity token.
4. Approve a response recommendation. The UI exposes that the action is disruptive and records approval in the audit trail.
5. Select **Propose detection**. The platform creates a draft rule with `sourceIncident` provenance.
6. Open **Replay lab** and run the macro chain scenario. The replay evaluates current detections and anomaly scores and writes a receipt to the audit trail.
7. Use **Learning loop** to confirm or dismiss the incident. Analyst feedback is retained as a labeled event rather than silently changing logic.

## API examples

```bash
# Read the dashboard
curl http://localhost:4173/api/dashboard

# Run a recorded replay
curl -X POST http://localhost:4173/api/replays \
  -H "Content-Type: application/json" \
  -d '{"scenario":"macro-chain"}'

# Propose a detection from evidence
curl -X POST http://localhost:4173/api/incidents/INC-2026-1042/propose-detection
```

### RBAC simulation

The API accepts `x-sentinalx-role` as a demo role header:

- `analyst` — investigate and record feedback, but cannot approve response or write detections.
- `engineer` — run replays and write detection proposals.
- `admin` — full demo permissions, including response approvals.

Example:

```bash
curl http://localhost:4173/api/detections -H "x-sentinalx-role: analyst"
```

## Design decisions worth discussing in an interview

### 1. Detection and anomaly scoring are independent

The replay engine does not treat a rule hit as the only definition of maliciousness. It records rule matches and an anomaly score separately, making it possible to inspect:

- rule precision and false-positive behavior;
- anomaly-only findings;
- cases where both systems agree;
- whether a proposed rule improves coverage without hiding model regressions.

### 2. Evidence is first-class

An incident stores event IDs, not copied prose alone. Investigation views resolve those IDs back into normalized events. This keeps the narrative explainable and makes the timeline/replay relationship explicit.

### 3. Disruptive responses are gated

Recommendations are not actions. Isolation, token revocation, and process termination require a role with `approve:response`; approval creates an audit record. This is the safer default for an AI analyst.

### 4. Learning is auditable

Feedback, replay completions, and detection proposals are all recorded. The platform deliberately avoids “magic” model changes that cannot be explained later.

## Validation

The repository includes tests for:

- incident correlation and evidence ordering;
- anomaly ranking of suspicious vs benign events;
- replay findings and audit receipts;
- detection proposal provenance;
- role permission boundaries.

Run them with:

```bash
npm test
```
