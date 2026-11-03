# ADR-0010: Three log sources behind one event model

* Status: accepted
* Date: 2026-10-31

## Context
Stage 2 left three telemetry questions open: does LocalStack deliver real CloudTrail log files to S3, is `StopLogging` recorded at all (S04 telemetry was `NONE`), and are S3 data events delivered (S02). `lookup_events` shows management events only and needs no delivery.

## Decision
The engine consumes `Event` objects and does not know where they came from. Three sources implement the same interface: log files from the trail's S3 destination, `lookup_events`, and a poller of `get_trail_status` that emits an observation event. `make detect-probe` measures what LocalStack provides and writes the recommended source to `build/logsource.json`. Rule `AEG-EVAS-002` is state-based so S04 stays detectable even when the `StopLogging` event was never written.

## Consequences
* (+) A LocalStack gap changes one source, not the rules. On real AWS the S3 source is the production path.
* (+) The probe turns open questions into recorded evidence before any rule depends on them.
* (-) The state poller only sees what is still true when it polls: a trail stopped and restarted within one interval is missed. Poll interval and dwell time are reported, not hidden.
* (-) The detector reads with the account root on LocalStack. On real AWS this would be a read-only role.