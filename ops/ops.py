#!/usr/bin/env python3
"""AegisCloud operations CLI (Stage 5).

  ops.py up | down                  start / stop the supervised detector + responder (checkpoint + resume on)
  ops.py status                     one health check, printed
  ops.py watchdog [--heal] [--publish] [--interval S] [--once]
  ops.py slo [--window-h H] [--write]
  ops.py drill [--bucket B] [--keep]
  ops.py chaos list | run ID [--label L] [--no-resume]
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from aegis_ops import chaos, drill, slo  # noqa: E402
from aegis_ops.components import Stack  # noqa: E402
from aegis_ops.probes import pid_alive  # noqa: E402
from aegis_ops.watchdog import CloudWatchPublisher, Watchdog  # noqa: E402

ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
WORKLOAD = "444444444444"


def _guard() -> None:
    from urllib.parse import urlparse
    if (urlparse(ENDPOINT).hostname or "").lower() not in {"localhost", "127.0.0.1", "localstack", "localstack.localhost"}:
        sys.exit(f"refusing to run: endpoint '{ENDPOINT}' is not LocalStack (this tool kills processes and deletes objects)")


def _client(service: str, account: str = WORKLOAD):
    import boto3
    return boto3.client(service, endpoint_url=ENDPOINT, region_name="us-east-1",
                        aws_access_key_id=account, aws_secret_access_key="test")


def watchdog_running(pid_file: Path) -> int | None:
    """The pid of a live watchdog, or None. A stale pid file (the watchdog was killed, or the pid was reused by some
    other process) must not block an experiment, so the process has to actually be an `ops.py watchdog`."""
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return None
    if not pid_alive(pid):
        return None
    try:
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return pid                      # no /proc: trust the pid
    return pid if "ops.py" in cmd and "watchdog" in cmd else None


def _event(rec: dict) -> None:
    path = ROOT / "build" / "ops" / "events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps({"ts": time.time(), "component": "-", "ok": True, **rec}) + "\n")


def stack(args) -> Stack:
    return Stack(ROOT, endpoint=ENDPOINT, opensearch=getattr(args, "opensearch", None) or None,
                 resume=not getattr(args, "no_resume", False))


def cmd_up(args) -> int:
    _guard()
    s = stack(args)
    _event({"action": "maintenance-end"})
    for name in ("detector", "responder"):
        print(f"{name}: {'up' if s.start(name) else 'FAILED to start (see build/ops/%s.log)' % name}")
    return 0 if all(s.probe(n).check().up for n in ("detector", "responder")) else 1


def cmd_down(args) -> int:
    s = stack(args)
    _event({"action": "maintenance-start"})     # stopped on purpose: not downtime, and the watchdog must not restart it
    for name in ("detector", "responder"):
        print(f"{name}: {'stopped' if s.kill(name, signal.SIGTERM) else 'was not running'}")
    return 0


def cmd_status(args) -> int:
    results = Watchdog(stack(args).probes(), ROOT / "build" / "ops").check()
    for r in results:
        print(f"{'UP  ' if r.up else 'DOWN'} {r.component:12} {r.detail}")
    return 0 if all(r.up for r in results) else 1


def cmd_watchdog(args) -> int:
    _guard()
    s = stack(args)
    pub = CloudWatchPublisher(_client("cloudwatch", "333333333333")) if args.publish else None
    s.ops.mkdir(parents=True, exist_ok=True)
    (s.ops / "watchdog.pid").write_text(str(os.getpid()))
    wd = Watchdog(s.probes(), s.ops, healers=s.healers() if args.heal else None, publisher=pub,
                  maintenance=lambda: slo.in_maintenance(s.ops / "events.jsonl"))
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    print(f"watchdog up: interval {args.interval}s, heal={'on' if args.heal else 'off'}, publish={'on' if args.publish else 'off'}", flush=True)

    def show(results):
        down = [f"{r.component} ({r.detail})" for r in results if not r.up]
        if down:
            print(time.strftime("%H:%M:%S"), "DOWN:", ", ".join(down), flush=True)
    if args.once:
        res = wd.check()
        if args.heal:
            wd.heal(res)
        show(res)
        return 0
    try:
        wd.run(args.interval, lambda: stop["flag"], heal=args.heal, on_check=show)
    finally:
        (s.ops / "watchdog.pid").unlink(missing_ok=True)      # a clean exit leaves no pid file behind
    return 0


def cmd_slo(args) -> int:
    config = json.loads((HERE / "slo.json").read_text())
    if args.window_h:
        config["window_h"] = args.window_h
    ops_dir = ROOT / "build" / "ops"
    epoch_file = ops_dir / "slo-epoch"
    if args.reset:
        ops_dir.mkdir(parents=True, exist_ok=True)
        epoch_file.write_text(str(time.time()))
        print("SLO history before now is ignored from here on (nothing was deleted). Run the stack, then `make ops-slo`.")
        return 0
    epoch = float(epoch_file.read_text()) if epoch_file.exists() else 0.0
    results = slo.evaluate(config, health_log=ops_dir / "health.jsonl", audit_path=Path(args.audit),
                           findings_dir=ROOT / "build" / "findings", now=time.time(), events_log=ops_dir / "events.jsonl", epoch=epoch)
    left_out = len(slo.chaos_windows(ops_dir / "events.jsonl")) + len(slo.maintenance_windows(ops_dir / "events.jsonl"))
    md = slo.render_markdown(results, config["window_h"], slo.now_stamp())
    if left_out:
        md += f"\n{left_out} chaos window(s) (chaos runs, or the stack stopped on purpose) were excluded.\n"
    print(md)
    if args.write:
        out = ROOT / "docs" / "evidence" / "slo"
        out.mkdir(parents=True, exist_ok=True)
        (out / "latest.md").write_text(md)
        (out / "latest.json").write_text(json.dumps(slo.to_json(results), indent=2))
        print(f"wrote {out}/latest.md and latest.json")
    return 1 if args.strict and any(r.status == "BREACHED" for r in results) else 0


def cmd_drill(args) -> int:
    _guard()
    res = drill.run_drill(_client("s3"), args.bucket, n=args.objects, keep=args.keep)
    print(res.line())
    if res.mismatches:
        print("not restored:", ", ".join(res.mismatches))
    out = ROOT / "docs" / "evidence" / "restore-drill.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({**res.__dict__, "bucket": args.bucket, "generated": slo.now_stamp()}, indent=2))
    return 0 if res.passed else 1


def cmd_chaos(args) -> int:
    if args.what == "list":
        for e in chaos.EXPERIMENTS.values():
            print(f"{e.id:24} {e.title}\n{'':24} hypothesis: {e.hypothesis}\n")
        return 0
    _guard()
    ids = list(chaos.EXPERIMENTS) if args.id in (None, "all") else [args.id]
    running = watchdog_running(ROOT / "build" / "ops" / "watchdog.pid")
    if running:
        sys.exit(f"a watchdog is running (pid {running}): it would restart the components behind the experiment's back "
                 f"and invalidate it. Stop it (Ctrl-C in its terminal, or `kill {running}`) and run again.")
    cfg = chaos.Config(resume=not args.no_resume)
    results = []
    for exp_id in ids:
        s = stack(args)
        for name in ("detector", "responder"):       # a clean, known start for every experiment
            s.kill(name)
        s.fresh_state(time.strftime("%Y%m%dT%H%M%S") + f"-{exp_id}")
        if not (s.start("detector") and s.start("responder")):
            print(f"{exp_id}: could not bring the stack up, see build/ops/*.log")
            return 1
        env = chaos.LiveEnv(s, f"{args.label}-{exp_id}", ENDPOINT)
        print(f"== {exp_id}", flush=True)
        _event({"action": "chaos-start", "experiment": exp_id})
        try:
            r = chaos.run(exp_id, env, cfg)
        finally:
            _event({"action": "chaos-end", "experiment": exp_id})
        print(f"   {r['verdict']}: {r['notes']}", flush=True)
        results.append(r)
        for name in ("detector", "responder"):
            s.kill(name, signal.SIGTERM)
    out = ROOT / "docs" / "evidence" / "chaos"
    out.mkdir(parents=True, exist_ok=True)
    if (out / f"{args.label}.json").exists():
        sys.exit(f"{args.label}.json exists: evidence is never overwritten, pick a new --label")
    (out / f"{args.label}.json").write_text(json.dumps(results, indent=2))
    (out / f"{args.label}.md").write_text(chaos.render_markdown(args.label, results))
    print(f"wrote {out}/{args.label}.md")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--opensearch", default=None, help="also probe OpenSearch, e.g. http://localhost:9200")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("up", cmd_up), ("down", cmd_down), ("status", cmd_status)):
        p = sub.add_parser(name)
        p.add_argument("--no-resume", action="store_true")
        p.set_defaults(fn=fn)
    w = sub.add_parser("watchdog")
    w.add_argument("--interval", type=float, default=5.0)
    w.add_argument("--heal", action="store_true")
    w.add_argument("--publish", action="store_true", help="publish ComponentUp to CloudWatch (LocalStack)")
    w.add_argument("--once", action="store_true")
    w.add_argument("--no-resume", action="store_true")
    w.set_defaults(fn=cmd_watchdog)
    s = sub.add_parser("slo")
    s.add_argument("--window-h", type=float, default=None)
    s.add_argument("--audit", default=str(ROOT / "build" / "ops" / "response" / "audit.jsonl"))
    s.add_argument("--write", action="store_true", help="write docs/evidence/slo/latest.*")
    s.add_argument("--reset", action="store_true", help="start measuring from now: ignore all earlier history (nothing is deleted)")
    s.add_argument("--strict", action="store_true", help="exit 1 when an SLO is breached (for CI or cron)")
    s.set_defaults(fn=cmd_slo)
    d = sub.add_parser("drill")
    d.add_argument("--bucket", default=f"aegis-data-{WORKLOAD}")
    d.add_argument("--objects", type=int, default=6)
    d.add_argument("--keep", action="store_true")
    d.set_defaults(fn=cmd_drill)
    c = sub.add_parser("chaos")
    c.add_argument("what", choices=["list", "run"])
    c.add_argument("id", nargs="?", help="experiment id or 'all'")
    c.add_argument("--label", default="stage5-run")
    c.add_argument("--no-resume", action="store_true", help="baseline: no checkpoint, no resume (the Stage 4 behaviour)")
    c.set_defaults(fn=cmd_chaos)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
