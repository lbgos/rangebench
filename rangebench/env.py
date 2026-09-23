"""Docker orchestration: per-attempt compose projects, attacker container, flag reads."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TASKS_DIR = ROOT / "tasks"
ATTACKER_IMAGE = "rb-attacker:latest"


class EnvError(RuntimeError):
    pass


@dataclass
class Stage:
    name: str
    flag_file: str
    service: str


@dataclass
class Task:
    id: str
    dir: Path
    category: str
    tier: int
    statement: str
    compose: str = "docker-compose.yml"
    attacker_networks: list[str] = field(default_factory=lambda: ["default"])
    deploy: list[str] = field(default_factory=list)  # copied into attacker /work
    shared_volumes: list[str] = field(
        default_factory=list
    )  # compose volume mounted into attacker, e.g. "incident:/work/incident:ro"
    stages: list[Stage] = field(default_factory=list)
    turns: int = 30
    cmd_timeout: int = 120
    infra_timeout: int = 180  # minutes, soft infra guard, not scoring
    max_tokens: int = 32768  # per-turn generation limit
    max_output_tokens: int = 800000  # total completion+reasoning budget, soft kill only
    ready_service: str = ""
    ready_cmd: str = ""
    canary: str = ""

    @property
    def is_range(self) -> bool:
        return len(self.stages) > 1


def load_task(task_id: str) -> Task:
    d = TASKS_DIR / task_id
    if not d.is_dir():
        known = ", ".join(sorted(p.name for p in TASKS_DIR.iterdir() if (p / "task.json").exists()))
        raise EnvError(f"unknown task {task_id}; known: {known}")
    raw = json.loads((d / "task.json").read_text())
    stages = [Stage(**s) for s in raw.get("stages", [])]
    if not stages:
        raise EnvError(f"{task_id}: at least one stage required")
    # wall_min is deprecated, map to infra_timeout for backward compat
    infra = raw.get("infra_timeout")
    if infra is None:
        infra = raw.get("wall_min", 180)
    return Task(
        id=task_id,
        dir=d,
        category=raw["category"],
        tier=int(raw["tier"]),
        statement=raw["statement"],
        compose=raw.get("compose", "docker-compose.yml"),
        attacker_networks=raw.get("attacker_networks", ["default"]),
        deploy=raw.get("deploy", []),
        shared_volumes=raw.get("shared_volumes", []),
        stages=stages,
        turns=int(raw.get("turns", 30)),
        cmd_timeout=int(raw.get("cmd_timeout", 120)),
        infra_timeout=int(infra),
        max_tokens=int(raw.get("max_tokens", 32768)),
        max_output_tokens=int(raw.get("max_output_tokens", 800000)),
        ready_service=raw.get("ready_service", ""),
        ready_cmd=raw.get("ready_cmd", ""),
        canary=raw.get("canary", ""),
    )


def load_all() -> list[Task]:
    return [load_task(p.name) for p in sorted(TASKS_DIR.iterdir()) if (p / "task.json").exists()]


def _run(cmd: list[str], timeout: int = 300, check: bool = True) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise EnvError(f"{' '.join(cmd[:6])}... timed out after {timeout}s") from exc
    if check and proc.returncode != 0:
        raise EnvError(f"{' '.join(cmd[:6])}... failed: {(proc.stderr or proc.stdout)[-800:]}")
    return proc


class TaskEnv:
    """One attempt of one task: fresh compose project + fresh attacker container."""

    def __init__(self, task: Task, project: str, attacker_image: str = ATTACKER_IMAGE):
        self.task = task
        self.project = project
        self.attacker = f"{project}-atk"
        self.attacker_image = attacker_image

    def up(self, build: bool = True) -> None:
        compose = [
            "docker",
            "compose",
            "-p",
            self.project,
            "-f",
            str(self.task.dir / self.task.compose),
        ]
        _run(compose + (["up", "-d", "--build"] if build else ["up", "-d"]), timeout=1800)
        if self.task.ready_service:
            deadline = time.time() + 180
            while time.time() < deadline:
                probe = _run(
                    compose
                    + ["exec", "-T", self.task.ready_service, "sh", "-c", self.task.ready_cmd],
                    timeout=60,
                    check=False,
                )
                if probe.returncode == 0:
                    break
                time.sleep(3)
            else:
                self.down()
                raise EnvError(f"{self.task.id}: readiness probe never passed")
        nets = []
        for net in self.task.attacker_networks:
            full = net if "_" in net else f"{self.project}_{net}"
            nets.append(full)
        vol_args: list[str] = []
        for v in self.task.shared_volumes:
            name, _, dest = v.partition(":")
            vol_args += ["-v", f"{self.project}_{name}:{dest}"]
        _run(["docker", "rm", "-f", self.attacker], check=False, timeout=60)
        # per-attempt pip cache isolation, no shared rb-pip-cache
        pip_vol = f"{self.project}-pip-cache:/root/.cache/pip"
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                self.attacker,
                "--network",
                nets[0],
                "--network-alias",
                "attacker",
                "--tmpfs",
                "/tmp:size=256m,mode=1777",
                "--ulimit",
                "fsize=2147483648",
                "-v",
                pip_vol,
                *vol_args,
                self.attacker_image,
                "sleep",
                "infinity",
            ],
            timeout=300,
        )
        for extra in nets[1:]:
            _run(["docker", "network", "connect", extra, self.attacker], check=False, timeout=60)
        if self.task.deploy:
            for path in self.task.deploy:
                src = self.task.dir / path
                if src.is_dir():
                    _run(
                        ["docker", "cp", str(src) + "/.", f"{self.attacker}:/work/{src.name}"],
                        timeout=120,
                    )
                else:
                    _run(["docker", "cp", str(src), f"{self.attacker}:/work/"], timeout=120)
        _run(
            ["docker", "exec", self.attacker, "chown", "-R", "agent:agent", "/work"],
            check=False,
            timeout=120,
        )

    def exec(
        self, cmd: str, timeout: int = 120, user: str = "agent", workdir: str = "/work"
    ) -> tuple[int, str]:
        """Run a bash command in the attacker container, return (rc, output)."""

        def attacker_available() -> bool:
            try:
                probe = subprocess.run(
                    ["docker", "exec", self.attacker, "true"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except subprocess.TimeoutExpired as exc:
                raise EnvError("Docker exec probe timed out") from exc
            return probe.returncode == 0

        try:
            proc = subprocess.run(
                ["docker", "exec", "-u", user, "-w", workdir, self.attacker, "bash", "-lc", cmd],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stderr = (proc.stderr or "").lstrip()
            # docker exec forwards command stderr, so confirm a matching
            # message is from Docker before invalidating the attempt.
            if (
                proc.returncode != 0
                and stderr.startswith(
                    (
                        "Cannot connect to the Docker daemon",
                        "error during connect:",
                        "Error response from daemon:",
                    )
                )
                and not attacker_available()
            ):
                raise EnvError(f"Docker exec failed before attacker command: {stderr[-300:]}")
            out = (proc.stdout or "") + (
                ("\n[stderr]\n" + proc.stderr) if proc.stderr.strip() else ""
            )
            return proc.returncode, out
        except subprocess.TimeoutExpired as exc:
            if not attacker_available():
                raise EnvError("Docker exec unavailable after attacker command timeout") from exc
            return 124, f"[command timed out after {timeout}s]"

    def read_flag(self, stage: Stage) -> str:
        compose = [
            "docker",
            "compose",
            "-p",
            self.project,
            "-f",
            str(self.task.dir / self.task.compose),
        ]
        proc = _run(
            compose + ["exec", "-T", "-u", "0", stage.service, "cat", stage.flag_file],
            timeout=60,
            check=False,
        )
        flag = (proc.stdout or "").strip()
        if proc.returncode != 0 or not flag:
            raise EnvError(
                f"cannot read flag {stage.service}:{stage.flag_file}: {(proc.stderr or '')[-300:]}"
            )
        return flag

    def logs(self, service: str, tail: int = 50) -> str:
        compose = [
            "docker",
            "compose",
            "-p",
            self.project,
            "-f",
            str(self.task.dir / self.task.compose),
        ]
        proc = _run(compose + ["logs", "--tail", str(tail), service], timeout=60, check=False)
        return proc.stdout or ""

    def down(self) -> tuple[bool, str]:
        """Best-effort teardown. Returns (ok, warning). Warning is non-empty if something failed but never kills caller."""
        if shutil.which("docker") is None:
            return True, ""
        warnings: list[str] = []
        for attempt in range(2):
            try:
                _run(["docker", "rm", "-f", self.attacker], check=False, timeout=45)
                break
            except Exception as exc:
                warnings.append(f"attacker rm attempt {attempt}: {exc}")
                continue
        try:
            _run(
                [
                    "docker",
                    "compose",
                    "-p",
                    self.project,
                    "-f",
                    str(self.task.dir / self.task.compose),
                    "down",
                    "-v",
                    "--remove-orphans",
                    "--timeout",
                    "10",
                ],
                check=False,
                timeout=300,
            )
        except Exception as exc:
            warnings.append(f"compose down: {exc}")
        # pip cache volume is per-attempt, remove it as well
        try:
            _run(["docker", "volume", "rm", f"{self.project}-pip-cache"], check=False, timeout=30)
        except Exception:
            pass
        ok = not warnings
        return ok, "; ".join(warnings)


def truncate_output(text: str, limit: int = 6000) -> str:
    if len(text) <= limit:
        return text
    head, tail = text[: limit // 2], text[-limit // 3 :]
    return f"{head}\n...[truncated {len(text) - len(head) - len(tail)} chars]...\n{tail}"
