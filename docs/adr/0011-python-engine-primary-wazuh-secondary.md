# ADR-0011: Python engine is the scored detector, Wazuh the second, OpenSearch replaces ELK

* Status: accepted
* Date: 2026-10-31

## Context
The roadmap lists Wazuh, ELK and Falco. Wazuh's AWS module reads CloudTrail from S3 and needs a working delivery path and a custom endpoint, which is itself unverified on LocalStack. Wazuh and ELK are heavy on a laptop. None of the 12 scenarios exercises a container.

## Decision
The Python engine owns collection and correlation and is the detector that produces the headline number (ADR-0002). It mirrors raw events as JSON lines; Wazuh reads that mirror with custom rules for single-event and simple-burst techniques, and a bridge turns its alerts into contract alerts (`source = wazuh`). OpenSearch + Dashboards replace ELK for storage and dashboards. Falco is optional and outside the 12.

## Consequences
* (+) One component carries the LocalStack uncertainty; each heavy component is added only after the Python path scores.
* (+) The scorer can credit one detector at a time (`--alert-source`), so Wazuh's contribution is measured, not assumed.
* (-) Wazuh does not read CloudTrail itself here, so "Wazuh ingests CloudTrail" is true only through our mirror. The README says so.
* (-) Wazuh covers 10 of the 12 techniques at best (not S01 discovery, not S08 client policy).