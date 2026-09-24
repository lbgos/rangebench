import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rangebench.agent import Usage
from rangebench.env import ATTACKER_IMAGE, EnvError, Stage, Task
from rangebench.runner import run_attempt, run_oracle


class FakeEnv:
    def __init__(self, task: Task, project: str, attacker_image: str = ATTACKER_IMAGE):
        self.attacker = f"{project}-atk"
        self.attacker_image = attacker_image

    def up(self) -> None:
        pass

    def read_flag(self, stage: Stage) -> str:
        return "flag{test}"

    def exec(self, cmd: str, **_kwargs: object) -> tuple[int, str]:
        return 0, "oracle did not find the flag" if cmd.startswith("bash /oracle") else ""

    def down(self) -> tuple[bool, str]:
        return True, ""


class AnswerClient:
    def chat(self, _messages: list[dict], max_tokens: int, temperature: float = 0.2) -> tuple[str, Usage, None]:
        return "ANSWER: flag{test}", Usage(), None


class RunnerTests(unittest.TestCase):
    def test_keep_writes_event_before_closing_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch("rangebench.runner.TaskEnv", FakeEnv):
            task = Task("sample", Path(tmp), "web", 1, "Find the flag", stages=[Stage("one", "/flag", "target")])
            result = run_attempt(AnswerClient(), task, 1, "rb-test", Path(tmp), verbose=False, keep=True)
            records = [json.loads(line) for line in (Path(tmp) / "sample-t1.jsonl").read_text().splitlines()]

        self.assertEqual(result.end_reason, "all stages captured")
        kinds = [record["kind"] for record in records]
        self.assertLess(kinds.index("keep"), kinds.index("end"))

    def test_oracle_failure_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            solution = Path(tmp) / "solution"
            solution.mkdir()
            (solution / "solve.sh").write_text("#!/bin/sh\nexit 0\n")
            task = Task("sample", Path(tmp), "web", 1, "Find the flag", stages=[Stage("one", "/flag", "target")])
            with patch("rangebench.runner.TaskEnv", FakeEnv), patch(
                "subprocess.run", return_value=SimpleNamespace(returncode=0, stderr="")
            ):
                with self.assertRaisesRegex(EnvError, "oracle failed"):
                    run_oracle(task)

    def test_oracle_dependency_copy_failure_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            solution = Path(tmp) / "solution"
            solution.mkdir()
            (solution / "solve.sh").write_text("#!/bin/sh\nexit 0\n")
            (solution / "helper.sh").write_text("#!/bin/sh\n")
            task = Task("sample", Path(tmp), "web", 1, "Find the flag", stages=[Stage("one", "/flag", "target")])
            copies = [
                SimpleNamespace(returncode=0, stderr=""),
                SimpleNamespace(returncode=1, stderr="copy failed"),
            ]
            with patch("rangebench.runner.TaskEnv", FakeEnv), patch(
                "subprocess.run", side_effect=copies
            ):
                with self.assertRaisesRegex(EnvError, "docker cp helper.sh"):
                    run_oracle(task)


if __name__ == "__main__":
    unittest.main()
