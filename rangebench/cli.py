"""CLI: list / check (oracle) / run (agent) / smoke."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import os
import statistics
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .agent import AnthropicChatClient, ChatClient, ChatClientProtocol
from .env import TASKS_DIR, load_all, load_task
from .runner import (
    DEFAULT_CTX_WINDOW,
    DEFAULT_KEEP_TAIL,
    DEFAULT_RESERVE,
    DEFAULT_THRESHOLD,
    run_attempt,
    run_oracle,
)

RESULTS = Path(__file__).resolve().parent.parent / "results"


def _wilson(p: float, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    delta = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - delta) / denom), min(1.0, (centre + delta) / denom)


def _get_git_commit() -> str | None:
    for cmd in (["git", "rev-parse", "HEAD"], ["git", "rev-parse", "--short", "HEAD"]):
        try:
            out = subprocess.run(
                cmd, cwd=TASKS_DIR.parent, capture_output=True, text=True, timeout=5
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip().splitlines()[0][:40]
        except Exception:
            continue
    return os.environ.get("RANGEBENCH_COMMIT")


def _get_attacker_digest() -> str | None:
    try:
        out = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", "rb-attacker:latest"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip().startswith("sha256:"):
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _get_task_set_hash() -> str:
    h = hashlib.sha256()
    for path in sorted(TASKS_DIR.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        h.update(str(path.relative_to(TASKS_DIR)).encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()[:16]


def _get_harness_hash() -> str:
    root = TASKS_DIR.parent
    paths = sorted((root / "rangebench").glob("*.py")) + [root / "pyproject.toml"]
    h = hashlib.sha256()
    for path in paths:
        h.update(str(path.relative_to(root)).encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()[:16]


def _write_manifest(log_dir: Path, doc: dict, extra: dict | None = None) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "manifest_version": 2,
        "id": doc.get("id"),
        "model": doc.get("model"),
        "base_url": doc.get("base_url"),
        "provider": doc.get("provider", "openai"),
        "ctx_window": doc.get("ctx_window"),
        "reserve": doc.get("reserve"),
        "keep_tail": doc.get("keep_tail"),
        "threshold": doc.get("threshold"),
        "compact": doc.get("compact"),
        "selected_tasks": doc.get("selected_tasks"),
        "trials": doc.get("trials"),
        "started": doc.get("started"),
        "finished": doc.get("finished"),
        "harness_commit": _get_git_commit(),
        "harness_source_hash": _get_harness_hash(),
        "attacker_digest": doc.get("attacker_digest"),
        "task_set_hash": _get_task_set_hash(),
        "task_count": len(doc.get("tasks", [])),
        "output_tokens_include_reasoning": True,
    }
    if extra:
        manifest.update(extra)
    tmp = log_dir / "manifest.json.tmp"
    tmp.write_text(json.dumps(manifest, indent=2))
    os.replace(tmp, log_dir / "manifest.json")


def _write_report_html(log_dir: Path, doc: dict) -> None:
    try:
        tasks = doc.get("tasks", [])
        rows = []
        for t in tasks:
            out_tok = t.get("completion_tokens", 0)
            status = "error" if not t.get("scored", True) else "pass" if t.get("solved") else "fail"
            color = "#10b981" if status == "pass" else "#ef4444" if status == "error" else "#9ca3af"
            rows.append(
                f"<tr><td>{html.escape(t.get('task', ''))}</td><td>{html.escape(t.get('category', ''))}</td><td>T{t.get('tier', '')}</td><td style='color:{color}'>{status}</td><td>{t.get('turns_used', 0)}/{t.get('turns_budget', 0)}</td><td>{out_tok}</td><td>{t.get('wall_s', 0)}</td><td>{html.escape(t.get('end_reason', ''))}</td></tr>"
            )
        scored = [t for t in tasks if t.get("scored", True)]
        solved = sum(1 for t in scored if t.get("solved"))
        total = len(scored)
        body = f"<h1>rangebench {html.escape(doc.get('id', ''))}</h1><p>model {html.escape(doc.get('model', ''))} - {solved}/{total} - {html.escape(doc.get('started', ''))}</p><table border=1 cellpadding=6><tr><th>task</th><th>cat</th><th>tier</th><th>result</th><th>turns</th><th>out tok</th><th>wall</th><th>end</th></tr>{''.join(rows)}</table>"
        html_doc = f"<!doctype html><meta charset=utf-8><title>rangebench {html.escape(doc.get('id', ''))}</title><style>body{{font-family:system-ui,sans-serif;margin:2rem}}table{{border-collapse:collapse}}th{{background:#f3f4f6}}</style>{body}"
        tmp = log_dir / "report.html.tmp"
        tmp.write_text(html_doc)
        os.replace(tmp, log_dir / "report.html")
    except Exception:
        pass


def cmd_list(_args: argparse.Namespace) -> None:
    tasks = load_all()
    print(
        f"{'id':24} {'cat':10} {'tier':4} {'stages':6} {'turns':5} {'infra':6} {'out-budget':10} statement"
    )
    for t in tasks:
        print(
            f"{t.id:24} {t.category:10} T{t.tier:<3} {len(t.stages):<6} {t.turns:<5} {t.infra_timeout:<6} {t.max_output_tokens:<10} {t.statement[:60]}"
        )


def cmd_check(args: argparse.Namespace) -> None:
    for tid in args.tasks:
        run_oracle(load_task(tid), project=f"rb-oracle-{uuid.uuid4().hex[:10]}")


def cmd_run(args: argparse.Namespace) -> None:
    if args.trials < 1:
        raise SystemExit("--trials must be at least 1")
    if args.ctx_window <= args.reserve or args.reserve < 0:
        raise SystemExit("--ctx-window must be greater than nonnegative --reserve")
    if args.keep_tail < 0 or not 0 < args.threshold < 1:
        raise SystemExit("--keep-tail must be nonnegative and --threshold must be between 0 and 1")
    task_ids = args.tasks if args.tasks else [t.id for t in load_all()]
    base = (
        os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1")
        if not args.base_url
        else args.base_url
    )
    if not args.base_url and "OPENAI_BASE_URL" not in os.environ:
        print(f"[warn] OPENAI_BASE_URL not set, using default {base}", flush=True)
    attacker_digest = _get_attacker_digest()
    if not attacker_digest:
        raise SystemExit("rb-attacker image ID unavailable; run preflight first")
    # provider switch
    provider = getattr(args, "provider", "openai")
    client: ChatClientProtocol
    if provider == "anthropic":
        client = AnthropicChatClient(
            base_url=base,
            api_key=os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("OPENAI_API_KEY", "dummy"),
            model=args.model,
        )
    else:
        client = ChatClient(
            base_url=base,
            api_key=os.environ.get("OPENAI_API_KEY", "dummy"),
            model=args.model,
        )
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    log_dir = RESULTS / run_id
    out = RESULTS / f"{run_id}.json"
    doc = {
        "id": run_id,
        "model": args.model,
        "base_url": base,
        "provider": provider,
        "attacker_digest": attacker_digest,
        "ctx_window": args.ctx_window,
        "reserve": args.reserve,
        "keep_tail": args.keep_tail,
        "threshold": args.threshold,
        "compact": args.compact,
        "selected_tasks": task_ids,
        "trials": args.trials,
        "started": datetime.now(UTC).isoformat(),
        "tasks": [],
    }
    # Fail before spending model calls if the manifest cannot be recorded.
    _write_manifest(log_dir, doc, extra={"status": "running"})
    for tid in task_ids:
        task = load_task(tid)
        for trial in range(1, args.trials + 1):
            project = f"rb-{task.id}-{trial}-{uuid.uuid4().hex[:6]}"
            use_llm = getattr(args, "compact", "deterministic") == "llm"
            res = run_attempt(
                client,
                task,
                trial,
                project,
                log_dir,
                keep=args.keep,
                ctx_window=args.ctx_window,
                reserve=args.reserve,
                keep_tail=args.keep_tail,
                threshold=args.threshold,
                use_llm_compact=use_llm,
                attacker_image=attacker_digest,
            )
            doc["tasks"].append(
                {
                    "task": task.id,
                    "category": task.category,
                    "tier": task.tier,
                    "trial": trial,
                    "solved_stages": res.solved,
                    "stages_total": [s.name for s in task.stages],
                    "solved": sorted(res.solved) == sorted(s.name for s in task.stages),
                    "scored": not (
                        res.end_reason.startswith("env:")
                        or res.end_reason
                        in {"infra timeout", "llm error", "context window exhausted"}
                    ),
                    "wrong": res.wrong,
                    "turns_used": res.turns_used,
                    "turns_budget": task.turns,
                    "commands": res.commands,
                    "prompt_tokens": res.prompt_tokens,
                    "completion_tokens": res.completion_tokens,
                    "reasoning_tokens": res.reasoning_tokens,
                    "compaction_tokens": res.compaction_tokens,
                    "wall_s": res.wall_s,
                    "end_reason": res.end_reason,
                    "max_output_tokens": task.max_output_tokens,
                }
            )
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(doc, indent=2))
            (RESULTS / "latest.json").write_text(json.dumps(doc, indent=2))
            _write_manifest(
                log_dir,
                doc,
                extra={
                    "status": "running",
                    "progress": f"{len(doc['tasks'])}/{len(task_ids) * args.trials}",
                },
            )
    doc["finished"] = datetime.now(UTC).isoformat()
    out.write_text(json.dumps(doc, indent=2))
    (RESULTS / "latest.json").write_text(json.dumps(doc, indent=2))
    invalid = sum(1 for t in doc["tasks"] if not t["scored"])
    _write_manifest(
        log_dir, doc, extra={"status": "completed_with_errors" if invalid else "completed"}
    )
    _write_report_html(log_dir, doc)
    print(f"wrote {out}")
    print(f"wrote {log_dir / 'manifest.json'} and {log_dir / 'report.html'}")
    scored = [t for t in doc["tasks"] if t["scored"]]
    solved = sum(1 for t in scored if t["solved"])
    total = len(scored)
    print(f"tasks solved: {solved}/{total} scored runs ({invalid} invalid)")
    from collections import defaultdict

    by_cat = defaultdict(list)
    for t in doc["tasks"]:
        by_cat[t["category"]].append(t)
    print("\nper-category:")
    for cat, lst in sorted(by_cat.items()):
        valid = [x for x in lst if x["scored"]]
        s = sum(1 for x in valid if x["solved"])
        print(f"  {cat:10} {s}/{len(valid)} ({len(lst) - len(valid)} invalid)")
    by_tier = defaultdict(list)
    for t in doc["tasks"]:
        by_tier[t["tier"]].append(t)
    print("per-tier:")
    for tier in sorted(by_tier):
        lst = by_tier[tier]
        valid = [x for x in lst if x["scored"]]
        s = sum(1 for x in valid if x["solved"])
        print(f"  T{tier} {s}/{len(valid)} ({len(lst) - len(valid)} invalid)")
    if args.trials > 1:
        p = solved / total if total else 0
        lo, hi = _wilson(p, total)
        print(f"overall Wilson 95%: {p:.2%} [{lo:.2%}, {hi:.2%}] n={total}")
    toks = [t["completion_tokens"] for t in doc["tasks"]]
    if toks:
        print(
            f"output tokens: mean {statistics.mean(toks):.0f} median {statistics.median(toks):.0f} max {max(toks)}"
        )
    print("\nper-task:")
    print(f"{'task':20} {'solved':6} {'turns':10} {'out_tok':10} {'wall':8} end")
    for t in doc["tasks"]:
        out_tok = t["completion_tokens"]
        print(
            f"{t['task']:20} {str(t['solved']):6} {t['turns_used']}/{t['turns_budget']:<6} {out_tok:<10} {t['wall_s']:<8} {t['end_reason']}"
        )
    if invalid:
        raise SystemExit(1)


def cmd_probe(args: argparse.Namespace) -> None:
    base = args.base_url or os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1")
    provider = getattr(args, "provider", "openai")
    client: ChatClientProtocol
    if provider == "anthropic":
        client = AnthropicChatClient(
            base,
            os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY", "dummy"),
            args.model,
        )
    else:
        client = ChatClient(base, os.environ.get("OPENAI_API_KEY", "dummy"), args.model)
    content, usage, err = client.chat(
        [{"role": "user", "content": "Reply with exactly: COMMAND:\necho ok"}], 512
    )
    print(f"err={err}\nusage={usage}\ncontent={content!r}")


def cmd_preflight(_args: argparse.Namespace) -> None:
    """Check docker, compose, and pull all task images without running tasks."""
    import shutil

    if shutil.which("docker") is None:
        print("docker not found", flush=True)
        raise SystemExit(1)
    subprocess.run(["docker", "version"], check=True)
    res = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
    if res.returncode != 0:
        print("docker compose not found, need docker compose plugin", flush=True)
        raise SystemExit(1)
    print(res.stdout.strip())
    root = TASKS_DIR.parent
    print("[preflight] building rb-attacker from current source...", flush=True)
    subprocess.run(
        ["docker", "build", "-t", "rb-attacker:latest", str(root / "attacker")],
        check=True,
    )
    digest = _get_attacker_digest()
    if not digest:
        raise SystemExit("rb-attacker image ID unavailable after build")
    print(f"attacker digest: {digest}")
    for task_dir in sorted(TASKS_DIR.iterdir()):
        compose = task_dir / "docker-compose.yml"
        if not compose.exists():
            continue
        print(f"[preflight] pulling {task_dir.name} ...", flush=True)
        subprocess.run(
            ["docker", "compose", "-f", str(compose), "pull", "--ignore-buildable", "--quiet"],
            check=True,
            timeout=600,
        )
    print(f"task set hash: {_get_task_set_hash()}")
    commit = _get_git_commit()
    if commit:
        print(f"harness commit: {commit}")
    print("preflight done")


def main() -> None:
    ap = argparse.ArgumentParser(prog="rangebench")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)
    chk = sub.add_parser("check", help="run oracle solutions against live envs")
    chk.add_argument("tasks", nargs="+")
    chk.set_defaults(func=cmd_check)
    run = sub.add_parser("run", help="run agent against tasks")
    run.add_argument("--model", required=True)
    run.add_argument(
        "--base-url",
        default=None,
        help="OpenAI base url, default $OPENAI_BASE_URL or http://localhost:8000/v1",
    )
    run.add_argument(
        "--provider", choices=["openai", "anthropic"], default="openai", help="wire format"
    )
    run.add_argument("tasks", nargs="*")
    run.add_argument("--trials", type=int, default=1)
    run.add_argument("--keep", action="store_true", help="skip teardown (debug)")
    run.add_argument(
        "--ctx-window",
        type=int,
        default=DEFAULT_CTX_WINDOW,
        help="context window for auto compaction",
    )
    run.add_argument(
        "--reserve", type=int, default=DEFAULT_RESERVE, help="reserve tokens for compaction output"
    )
    run.add_argument(
        "--keep-tail",
        type=int,
        default=DEFAULT_KEEP_TAIL,
        help="tail turns kept verbatim after compaction",
    )
    run.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="compaction threshold fraction of ctx window",
    )
    run.add_argument(
        "--compact",
        choices=["deterministic", "llm"],
        default="deterministic",
        help="compaction mode, deterministic is default, llm is opt-in ablation",
    )
    run.set_defaults(func=cmd_run)
    probe = sub.add_parser("probe")
    probe.add_argument("--model", required=True)
    probe.add_argument("--base-url", default=None)
    probe.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    probe.set_defaults(func=cmd_probe)
    pf = sub.add_parser("preflight", help="pull all images and check docker setup")
    pf.set_defaults(func=cmd_preflight)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
