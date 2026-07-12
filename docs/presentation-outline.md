# ThreatLens AI — Presentation Outline

A screenshot-driven deck outline for demoing **ThreatLens AI**, the AI-powered
threat-intelligence platform. Each slide lists what to capture, the explanation
text to put on the slide, and which agent (if any) drives that flow.

> **Suggested order:** Title → Architecture → Meet the Agents → Home → Threat Feed →
> Analyze CVE (input) → Analyze CVE (result) → Execution Trace → Industry Intelligence →
> SBOM Analysis → Reports → (Pipeline diagram) → API Docs → Closing.

---

## Agent-to-flow reference

Five specialized agents plus a LangGraph orchestrator:

| Agent | Backend endpoint | Data sources | LLM? |
| --- | --- | --- | --- |
| 🔍 **Threat Intelligence Agent** | `/cve/analyze`, `/threat-intelligence/report` | CISA KEV + NVD | ✅ OpenAI |
| 🏭 **Industry Intelligence Agent** | `/industry/report` | `industries.json` profiles | ✅ OpenAI |
| 📦 **Exposure Agent** | `/sbom/analyze` | CycloneDX SBOM | ❌ parse-based |
| ⚖️ **Risk Agent** | (pipeline only) | Threat + Industry + Exposure signals | ❌ deterministic |
| 📝 **Advisor Agent** | `/advisor/report`, `/orchestrate/report` | All of the above | ✅ OpenAI |
| ⚙️ **LangGraph Orchestrator** | `/orchestrate/report` | Routes all agents | — |

---

## Slide 1 — Title / Landing (Home page)

- **Screenshot:** Full window — sidebar (🛡️ ThreatLens AI nav + 🟢 Backend online),
  the four metric cards, the 14-day bar chart, "Latest CISA KEV" table beside
  "Recent Critical CVEs" cards.
- **Agent:** None — direct read of the CISA KEV feed via `/threats/latest`.
- **Slide text:**
  > **ThreatLens AI — AI-powered threat intelligence.** The Home dashboard gives a
  > real-time snapshot of CISA's Known Exploited Vulnerabilities: key stats (tracked
  > entries, ransomware-linked, unique vendors, added in last 7 days), a trend chart
  > of new entries, and the latest critical CVEs at a glance. Ransomware-linked
  > vulnerabilities are surfaced first.

## Slide 2 — Architecture (diagram, no screenshot)

- **Visual:** Reuse the Mermaid flowchart from the README (User → Streamlit → FastAPI
  → agents → CISA / NVD / OpenAI).
- **Slide text:**
  > **API-first, agent-driven.** A Streamlit dashboard talks to a FastAPI backend over
  > REST/JSON. The backend orchestrates five agents that draw on public CISA KEV and
  > NVD feeds plus an LLM to turn raw vulnerability data into executive-ready output.

## Slide 3 — Meet the Agents (overview, no screenshot)

- **Slide text:**
  > **Five specialized agents, one pipeline.**
  > - 🔍 **Threat Intelligence** — merges CISA KEV + NVD, generates a CVE report *(LLM)*
  > - 🏭 **Industry Intelligence** — executive briefing per industry *(LLM)*
  > - 📦 **Exposure** — attack-surface profile from an SBOM *(deterministic)*
  > - ⚖️ **Risk** — combines threat + industry + exposure into a risk score *(deterministic)*
  > - 📝 **Advisor** — synthesizes a final Markdown advisory *(LLM)*
  >
  > Orchestrated by a typed **LangGraph** state machine with conditional routing
  > (Exposure runs only when an SBOM is supplied).

## Slide 4 — Threat Feed

- **Screenshot:** Threat Feed page with the search box filled (e.g. "Microsoft"),
  severity + ransomware filters, the "Showing X of Y" caption, and the results table.
- **Agent:** None — same `/threats/latest` feed, client-side search and filtering.
- **Slide text:**
  > **Browse the full CISA KEV catalog.** Search by CVE, vendor, or product and filter
  > by severity and ransomware-campaign use. Load 20–200 entries on demand — the
  > analyst's starting point for triage.

## Slide 5 — Analyze CVE (input + live progress)

- **Screenshot:** The Analyze CVE form with a CVE entered, and the expanded status
  panel showing live steps ("Querying CISA KEV… Enriching with NVD… Merging sources…").
- **Agent:** 🔍 **Threat Intelligence Agent** (`/cve/analyze`).
- **Slide text:**
  > **Single-CVE deep dive, powered by the Threat Intelligence Agent.** Enter any CVE
  > and the agent queries the CISA KEV catalog, enriches it with NVD data, and generates
  > a structured report — with transparent, live progress at each step.

## Slide 6 — Analyze CVE (result view)

- **Screenshot:** CVE header + severity badge, four metric cards (CVSS score, Known
  Exploited, Model, Execution Time), Executive & Technical summaries, CVSS panel and
  Threat Timeline side-by-side.
- **Agent:** 🔍 **Threat Intelligence Agent**.
- **Slide text:**
  > **From raw feeds to an executive-ready brief.** The report pairs machine data
  > (CVSS breakdown, exploitation status, threat timeline) with AI-generated narrative —
  > executive summary, technical summary, business impact, likely attack scenario, and
  > immediate recommendations.

## Slide 7 — Analyze CVE (Agent execution trace)

- **Screenshot:** The expanded "Agent execution trace" showing the ✅ steps (CISA KEV
  lookup, NVD enrichment, Intelligence merge, AI report generation). Optionally the
  "Raw merged intelligence" JSON expander open too.
- **Agent:** 🔍 **Threat Intelligence Agent** (self-reported trace).
- **Slide text:**
  > **Explainable, auditable AI.** Every report includes a verified step-by-step trace
  > of exactly what the agent did and which sources it consulted — no black box. The raw
  > merged CISA KEV + NVD payload is one click away.

## Slide 8 — Industry Intelligence

- **Screenshot:** After generating a briefing — metric cards (Top Threats, Attack
  Patterns, APT Groups, Recommended Controls), the Executive Briefing container, the
  🎭 APT Threat Actors chips, and the Top Threats / Attack Patterns columns.
- **Agent:** 🏭 **Industry Intelligence Agent** (`/industry/report`).
- **Slide text:**
  > **Industry-tailored security briefings.** Pick an industry (e.g. Financial Services,
  > Healthcare) and the Industry Intelligence Agent produces an executive briefing: the
  > top threats, common attack patterns, APT groups known to target that sector, and
  > recommended controls.

## Slide 9 — SBOM Analysis

- **Screenshot:** After uploading a CycloneDX SBOM — metric cards (Components,
  Applications, Public Services, Internet Exposed), the Affected Components table,
  application chips, and the Risk row (Exposed Assets, Third-Party Exposure, Data
  Sensitivity badge).
- **Agent:** 📦 **Exposure Agent** (`/sbom/analyze`).
- **Slide text:**
  > **Know your attack surface.** Upload a CycloneDX SBOM and the Exposure Agent
  > enumerates components and applications, then derives an exposure profile — public
  > services, internet exposure, third-party risk, and data sensitivity — deterministically,
  > with concrete recommendations. No LLM involved.

## Slide 10 — Reports (full advisory)

- **Screenshot:** The Reports page — Priority / Overall Risk / Confidence metrics at
  top, the rendered Markdown advisory below, and the "Download Report (.md)" button.
- **Agents:** ⚙️ **LangGraph Orchestrator** running all five —
  🔍 Threat Intelligence → 🏭 Industry → 📦 Exposure *(only if an SBOM is attached)* →
  ⚖️ **Risk Agent** → 📝 **Advisor Agent** (`/orchestrate/report`).
- **Slide text:**
  > **One click, full advisory.** The Reports page runs the entire LangGraph pipeline
  > and synthesizes everything into a single downloadable Markdown security advisory.
  > The **Risk Agent** deterministically scores threat + industry + exposure signals;
  > the **Advisor Agent** turns it into the final narrative — with a risk score, priority,
  > and confidence. This is the only screen where the Risk and Advisor agents surface.

## Slide 11 — Orchestration Pipeline (diagram, no screenshot)

- **Visual:** Reuse the second Mermaid chart from the README (conditional LangGraph
  routing — Exposure runs only when an SBOM is supplied).
- **Slide text:**
  > **A typed, conditionally-routed state machine.** The pipeline branches on whether an
  > SBOM was uploaded, so the Exposure Agent only runs when it has something to analyze —
  > keeping the flow efficient and every run reproducible.

## Slide 12 — API Docs (optional)

- **Screenshot:** `http://localhost:8000/docs` — the FastAPI Swagger UI listing
  `/threats/latest`, `/cve/analyze`, `/industry/report`, `/sbom/analyze`,
  `/orchestrate/report`, etc.
- **Agents:** All — each agent is exposed as its own REST endpoint.
- **Slide text:**
  > **API-first.** Every capability is a documented REST endpoint. The Streamlit
  > dashboard is just one client — the FastAPI backend can power SIEM integrations,
  > automation, or other tooling.

## Slide 13 — Closing

- **Slide text:**
  > **ThreatLens AI** — from public feeds to executive-ready advisories, with explainable,
  > auditable agents. Built for authorized security research, CTF, and defensive use.
  > *Data sourced from CISA KEV and NVD.*

---

## Screenshot capture checklist

- Live screens need the backend running and valid keys in `.env`:
  - `OPENAI_API_KEY` — Analyze CVE, Industry Intelligence, Reports (Advisor).
  - `NVD_API_KEY` — Analyze CVE, Reports.
- Read-only screens (Home, Threat Feed) need only the CISA KEV feed — no keys.
- Suggested capture CVEs: use a well-known KEV entry (e.g. `CVE-2024-3400`) so the
  report is rich. See `docs/examples/` for representative outputs.
- Run locally: backend `uvicorn threatlens_ai.backend.main:app --port 8000`,
  frontend `streamlit run threatlens_ai/frontend/app.py` (dashboard on `:8501`).
