import argparse
import json
import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from rangebench.agent import Usage
from rangebench.cli import _get_task_set_hash, cmd_run
from rangebench.env import EnvError, Stage, Task, TaskEnv, _run
from rangebench.runner import AttemptResult


class AccountingTests(unittest.TestCase):
    def test_reasoning_is_part_of_completion_tokens(self) -> None:
        usage = Usage()
        usage.add(
            {
                "prompt_tokens": 10,
                "completion_tokens": 40,
                "completion_tokens_details": {"reasoning_tokens": 30},
            }
        )
        self.assertEqual(usage.completion_tokens, 40)
        self.assertEqual(usage.reasoning_tokens, 30)

    def test_challenge_code_changes_task_set_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tasks = Path(tmp) / "tasks"
            challenge = tasks / "sample" / "app.py"
            challenge.parent.mkdir(parents=True)
            (challenge.parent / "task.json").write_text('{"id":"sample"}')
            challenge.write_text("print('old')")
            with patch("rangebench.cli.TASKS_DIR", tasks):
                original = _get_task_set_hash()
                challenge.write_text("print('new')")
                changed = _get_task_set_hash()
        self.assertNotEqual(original, changed)

    def test_docker_timeout_is_an_environment_error(self) -> None:
        with patch("rangebench.env.subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 1)):
            with self.assertRaisesRegex(EnvError, "timed out after 1s"):
                _run(["docker", "compose", "up"], timeout=1)

    def test_docker_daemon_outage_is_not_a_model_command_failure(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        exec_failure = subprocess.CompletedProcess(
            [], 1, "", "Cannot connect to the Docker daemon"
        )
        probe_failure = subprocess.CompletedProcess([], 1, "", "daemon unavailable")
        with patch("rangebench.env.subprocess.run", side_effect=[exec_failure, probe_failure]):
            with self.assertRaisesRegex(EnvError, "Docker daemon unavailable"):
                env.exec("echo ok")

    def test_invalid_trial_exits_nonzero_after_writing_artifacts(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag", stages=[Stage("one", "/flag", "web")])
        args = argparse.Namespace(
            trials=1, ctx_window=128000, reserve=12000, keep_tail=12, threshold=0.82,
            tasks=[task.id], base_url="http://localhost:8000/v1", provider="openai",
            model="test", compact="deterministic", keep=False,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("rangebench.cli.RESULTS", Path(tmp)),
                patch("rangebench.cli.load_task", return_value=task),
                patch("rangebench.cli.ChatClient"),
                patch("rangebench.cli.run_attempt", return_value=AttemptResult(task.id, 1, end_reason="llm error")),
                patch("rangebench.cli._get_attacker_digest", return_value="sha256:test"),
            ):
                with self.assertRaises(SystemExit) as caught:
                    cmd_run(args)
            self.assertEqual(caught.exception.code, 1)
            self.assertEqual(json.loads((Path(tmp) / "latest.json").read_text())["tasks"][0]["scored"], False)
            manifest = next(Path(tmp).glob("*/manifest.json"))
            self.assertEqual(json.loads(manifest.read_text())["status"], "completed_with_errors")


if __name__ == "__main__":
    unittest.main()
