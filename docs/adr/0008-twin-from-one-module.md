# ADR-0008: Vulnerable and hardened twins from one module

* Status: accepted
* Date: 2026-10-30

## Context
"Prevent / detect / neither" needs a target that can prevent. We also want the claim "same code, different posture" to be provable.

## Decision
Module `range-target` takes `hardened` (bool). The hardened twin is a member account under OU `workloads` (SCPs apply) and reuses the Stage 1 `iam-baseline` permission boundary.

## Consequences
* (+) One set of victim assets, so every scenario runs unchanged against both.
* (+) `terraform test` asserts each twin's posture.
* (-) The hardened trail cannot be reconfigured or deleted by Terraform (SCP denies it); teardown is `make reset`. This is accepted and documented.