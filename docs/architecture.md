# Architecture

AegisCloud is a loop: **build, attack, detect, respond, operate, prove**. This page shows the parts and how data moves between
them. Everything drawn exists in the repo; the table at the end gives the path of each box (a test checks they exist). What is
*not* connected is marked in the last section: the diagram would otherwise look more finished than the system is.

The diagrams are Mermaid and render on GitHub. They were written without a renderer available, so if one does not draw, the
text under it is the source of truth.

## 1. The whole system

```mermaid
flowchart LR
  subgraph BUILD["Build (Stage 1)"]
    TF["Terraform modules + live roots"]
    CI["CI gates: fmt, validate, tflint, Checkov, Conftest, terraform test"]
    TF --> CI
  end

  subgraph RANGE["Attack (Stage 2)"]
    PURPLE["Purple twin: deliberately weak"]
    HARD["Hardened twin: same shape, controls on"]
    ATT["12 attack scenarios, each with an ATT&CK id"]
    ATT --> PURPLE
    ATT --> HARD
  end

  subgraph DETECT["Detect (Stage 3)"]
    TRAIL["CloudTrail"]
    ARCH["Trail bucket: central log archive, or the range twin's own"]
    ENGINE["Python detection engine, 14 rules"]
    ASFF["ASFF findings"]
    WAZ["Wazuh rules and OpenSearch dashboards"]
    TRAIL --> ARCH --> ENGINE --> ASFF
    ENGINE -. "JSON mirror" .-> WAZ
  end

  subgraph RESPOND["Respond (Stage 4)"]
    RESP["Responder: plan, ask, contain, verify"]
    APPR["Approver: Slack reaction or terminal"]
    PLAY["Playbooks: leaked key, public bucket"]
    AUDIT["Hash-chained audit log"]
    N8N["n8n webhook: told, cannot trigger"]
    RESP --> APPR
    APPR --> RESP
    RESP --> PLAY
    RESP --> AUDIT
    RESP -.-> N8N
  end

  subgraph OPERATE["Operate (Stage 5)"]
    WD["Watchdog and heartbeats"]
    CK["Checkpoint and resume"]
    DRILL["Backup and restore drill"]
    SLO["SLOs and error budgets"]
  end

  subgraph INTEL["Intelligence (Stage 6)"]
    SENT["IAM Sentinel: escalation paths, least privilege"]
    TRI["Triage: advisory note"]
  end

  subgraph SHIP["Ship (Stage 7)"]
    PKG["Reproducible Lambda zip"]
    SBOM["CycloneDX SBOM"]
    SIGN["cosign signature and attestation"]
    PKG --> SBOM --> SIGN
  end

  CI -->|"apply"| PURPLE
  PURPLE -->|"events"| TRAIL
  HARD -->|"events"| TRAIL
  ASFF -->|"build/findings"| RESP
  SENT -->|"scan.json"| TRI
  ASFF --> TRI
  TRI -.->|"advice lines, display only"| APPR
  SENT -.->|"reads IAM"| PURPLE
  WD -.->|"restarts"| ENGINE
  WD -.->|"restarts"| RESP
  CK -.-> ENGINE
  CK -.-> RESP
  RESP -.-> PKG
```

Solid arrows carry data a component needs. Dashed arrows are optional or advisory: nothing downstream of a dashed arrow
waits for it.

## 2. Accounts (all simulated on LocalStack by 12-digit access keys, ADR-0001)

```mermaid
flowchart TB
  MGMT["management 111111111111: organization, SCPs"]
  LOGA["log-archive 222222222222: logging module, central log bucket"]
  SEC["security 333333333333: pipeline-health alarms (monitoring module)"]
  WORK["workload 444444444444: network, data, compute, backup, patching"]
  RP["range purple 555555555555: weak twin and its own trail bucket"]
  RH["range hardened, generated account id: same shape, controls on, own trail bucket"]
  DET["detector reads the trail bucket of the account under test"]
  RP -->|"CloudTrail to its own bucket"| DET
  RH -->|"CloudTrail to its own bucket"| DET
  LOGA -->|"logging module takes source account ids"| DET
```

The `terraform/live/` roots are management, log-archive, security and workload. The two range twins are a separate Terraform
tree (`cloudpurple/terraform/`) so a deliberately weak account can never share state with the landing zone.

## 3. One incident, end to end

```mermaid
sequenceDiagram
  participant A as Attack scenario
  participant C as CloudTrail and archive
  participant D as Detector
  participant R as Responder
  participant T as Triage
  participant H as Person (approver)
  participant AWS as AWS APIs
  A->>C: API call (for example a secret is read)
  C->>D: log file
  D->>R: ASFF finding
  R->>R: plan (read-only)
  R->>T: incident and plan
  T-->>R: advisory lines (may be empty, never blocks)
  R->>H: plan, then advice
  H->>R: approve or deny (silence is a denial)
  R->>AWS: contain, exactly the plan that was shown
  R->>AWS: verify
  R->>R: append to the audit chain
```

The triage step cannot change the plan, the decision or what runs (ADR-0020). Its lines are appended after the plan.

## 4. Components and where they live

| Box | Path |
| --- | --- |
| Terraform modules | `terraform/modules/` |
| Live roots (accounts) | `terraform/live/` |
| CI gates | `.github/workflows/terraform-ci.yml`, `policies/` |
| Attack scenarios, twins | `cloudpurple/attacks/`, `cloudpurple/terraform/` |
| Detection engine | `detections/aegis_detect/` |
| Wazuh rules, OpenSearch, Falco rules | `siem/` |
| Responder, playbooks, approvers, audit | `response/aegis_respond/` |
| Watchdog, SLOs, drill, chaos | `ops/aegis_ops/` |
| IAM Sentinel | `sentinel/aegis_sentinel/` |
| Triage | `triage/aegis_triage/` |
| SBOM, signing, headline numbers | `release/` |

## 5. What is not connected

* **No live path from the detector to the Lambda.** The Lambda handler and its package exist and are tested with moto, but
  whether EventBridge on LocalStack delivers to it has not been tested (`docs/response-playbooks.md`).
* **Falco has rules and a bridge, not a scenario.** None of the 12 attacks exercises a container, so there is no measured
  Falco detection (ADR-0011).
* **n8n is told, it does not decide.** It receives incidents through a webhook; it cannot approve or trigger containment (ADR-0015).
* **Sentinel and triage are advisory.** Sentinel's findings go to `build/sentinel/findings/`, not `build/findings/`, so the responder never
  mistakes a standing weakness for an incident.
* **The measured approval was simulated.** The headline response run used an automatic approver; see `docs/lessons-learned.md`.
