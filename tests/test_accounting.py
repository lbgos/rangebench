import argparse
import json
import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from rangebench.agent import Usage
from rangebench.cli import _get_git_commit, _get_task_set_hash, cmd_preflight, cmd_run
from rangebench.env import EnvError, Stage, Task, TaskEnv, _run
from rangebench.runner import AttemptResult, _maybe_compact


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

    def test_openai_cache_and_missing_metadata_are_distinct(self) -> None:
        usage = Usage()
        usage.add(
            {
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "prompt_tokens_details": {"cached_tokens": 60},
                "completion_tokens_details": {"reasoning_tokens": 30},
            }
        )
        usage.add({"prompt_tokens": 20, "completion_tokens": 5})
        self.assertEqual((usage.input_tokens, usage.output_tokens), (120, 45))
        self.assertEqual(usage.cache_read_tokens, 60)
        self.assertIsNone(usage.cache_write_tokens)
        self.assertEqual((usage.cache_read_reported_calls, usage.calls), (1, 2))

        zero = Usage()
        zero.add(
            {
                "input_tokens": 10,
                "output_tokens": 4,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 3},
            }
        )
        self.assertEqual(zero.cache_read_tokens, 0)
        self.assertEqual(zero.reasoning_tokens, 3)

    def test_anthropic_input_includes_both_cache_buckets(self) -> None:
        usage = Usage()
        usage.add(
            {
                "input_tokens": 20,
                "cache_creation_input_tokens": 100,
                "cache_read_input_tokens": 200,
                "output_tokens": 30,
            },
            provider="anthropic",
        )
        self.assertEqual((usage.input_tokens, usage.output_tokens), (320, 30))
        self.assertEqual((usage.cache_read_tokens, usage.cache_write_tokens), (200, 100))
        self.assertEqual(
            (usage.cache_read_reported_calls, usage.cache_write_reported_calls), (1, 1)
        )

    def test_compaction_usage_is_separate_and_in_total(self) -> None:
        class Compactor:
            def chat(self, messages: list[dict], max_tokens: int, temperature: float = 0.2):
                usage = Usage()
                usage.add(
                    {
                        "prompt_tokens": 200,
                        "completion_tokens": 50,
                        "prompt_tokens_details": {"cached_tokens": 100},
                    }
                )
                return "state snapshot", usage, None

        res = AttemptResult("sample", 1)
        events: list[tuple[str, dict]] = []
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "task"},
            *(
                message
                for _ in range(3)
                for message in (
                    {"role": "assistant", "content": "history " * 250},
                    {"role": "user", "content": "observation"},
                )
            ),
        ]
        compacted = _maybe_compact(
            Compactor(),
            messages,
            res,
            ctx_window=3000,
            reserve=100,
            keep_tail=1,
            threshold=0.3,
            use_llm=True,
            emit=lambda kind, **kv: events.append((kind, kv)),
        )
        self.assertLess(len(compacted), len(messages))
        self.assertEqual(res.compaction_tokens, 250)
        self.assertEqual(res.total_usage().input_tokens, 200)
        self.assertEqual(res.total_usage().cache_read_tokens, 100)
        self.assertEqual(events[0][0], "compaction-call")
        self.assertEqual(events[0][1]["usage"]["cache_read_tokens"], 100)

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
        with patch(
            "rangebench.env.subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 1)
        ):
            with self.assertRaisesRegex(EnvError, "timed out after 1s"):
                _run(["docker", "compose", "up"], timeout=1)

    def test_docker_daemon_outage_is_not_a_model_command_failure(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        exec_failure = subprocess.CompletedProcess([], 1, "", "Cannot connect to the Docker daemon")
        probe_failure = subprocess.CompletedProcess([], 1, "", "daemon unavailable")
        with patch("rangebench.env.subprocess.run", side_effect=[exec_failure, probe_failure]):
            with self.assertRaisesRegex(EnvError, "Docker exec failed"):
                env.exec("echo ok")

    def test_dead_attacker_container_is_not_a_model_command_failure(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        failure = subprocess.CompletedProcess(
            [], 1, "", "Error response from daemon: Container rb-test-atk is not running"
        )
        probe_failure = subprocess.CompletedProcess([], 1, "", "container not running")
        with patch("rangebench.env.subprocess.run", side_effect=[failure, probe_failure]):
            with self.assertRaisesRegex(EnvError, "Docker exec failed"):
                env.exec("echo ok")

    def test_model_stderr_that_looks_like_docker_error_is_scored(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        command = subprocess.CompletedProcess([], 1, "", "Error response from daemon: pretend")
        probe = subprocess.CompletedProcess([], 0, "", "")
        with patch("rangebench.env.subprocess.run", side_effect=[command, probe]):
            rc, out = env.exec("printf 'Error response from daemon: pretend' >&2; exit 1")
        self.assertEqual(rc, 1)
        self.assertIn("pretend", out)

    def test_attacker_uses_recorded_image_id(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test", "sha256:recorded")
        with (
            patch("rangebench.env._run") as run,
            patch.object(env, "_verify_compose_config"),
            patch.object(env, "verify_isolation"),
        ):
            env.up()
        docker_run = next(
            call.args[0] for call in run.call_args_list if call.args[0][:2] == ["docker", "run"]
        )
        self.assertEqual(docker_run[-3:], ["sha256:recorded", "sleep", "infinity"])

    def test_attacker_command_timeout_is_enforced_inside_container(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        timed_out_command = subprocess.CompletedProcess(
            [], 124, "", "timeout: sending signal TERM to command ‘bash’"
        )
        with patch(
            "rangebench.env.subprocess.run",
            return_value=timed_out_command,
        ) as run:
            rc, out = env.exec("sleep 10", timeout=1)
        self.assertEqual((rc, out), (124, "[command timed out after 1s]"))
        self.assertEqual(
            run.call_args.args[0][-9:],
            [
                "timeout",
                "--verbose",
                "--kill-after=5s",
                "1",
                "bash",
                "-lc",
                'exec 2>&1; exec bash -lc "$1"',
                "_",
                "sleep 10",
            ],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 16)

    def test_command_exit_124_keeps_its_output(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        command = subprocess.CompletedProcess([], 124, "result", "")
        with patch("rangebench.env.subprocess.run", return_value=command):
            self.assertEqual(env.exec("printf result; exit 124"), (124, "result"))

    def test_kill_escalation_is_reported_as_command_timeout(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        command = subprocess.CompletedProcess(
            [], 137, "", "timeout: sending signal TERM to command ‘bash’\n"
        )
        with patch("rangebench.env.subprocess.run", return_value=command):
            self.assertEqual(env.exec("sleep 10", timeout=1), (124, "[command timed out after 1s]"))

    def test_docker_timeout_is_not_scored_when_attacker_is_unavailable(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        failed_probe = subprocess.CompletedProcess([], 1, "", "container not running")
        with patch(
            "rangebench.env.subprocess.run",
            side_effect=[subprocess.TimeoutExpired("docker exec", 1), failed_probe],
        ):
            with self.assertRaisesRegex(EnvError, "Docker exec unavailable"):
                env.exec("sleep 10", timeout=1)

    def test_outer_timeout_is_invalid_even_when_attacker_responds(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        healthy_probe = subprocess.CompletedProcess([], 0, "", "")
        with patch(
            "rangebench.env.subprocess.run",
            side_effect=[subprocess.TimeoutExpired("docker exec", 16), healthy_probe],
        ):
            with self.assertRaisesRegex(EnvError, "did not finish"):
                env.exec("sleep 10", timeout=1)

    def test_invalid_trial_exits_nonzero_after_writing_artifacts(self) -> None:
        task = Task(
            "sample", Path("/tmp"), "web", 1, "Find the flag", stages=[Stage("one", "/flag", "web")]
        )
        args = argparse.Namespace(
            trials=1,
            ctx_window=128000,
            reserve=12000,
            keep_tail=12,
            threshold=0.82,
            tasks=[task.id],
            base_url="http://localhost:8000/v1",
            provider="openai",
            model="test",
            compact="deterministic",
            keep=False,
        )
        result = AttemptResult(task.id, 1, end_reason="llm error")
        result.model_usage.add(
            {
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "prompt_tokens_details": {"cached_tokens": 60},
            }
        )
        result.compaction_usage.add(
            {
                "prompt_tokens": 20,
                "completion_tokens": 5,
                "prompt_tokens_details": {"cached_tokens": 0},
            }
        )
        result.prompt_tokens = 100
        result.completion_tokens = 40
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("rangebench.cli.RESULTS", Path(tmp)),
                patch("rangebench.cli.load_task", return_value=task),
                patch("rangebench.cli.ChatClient"),
                patch(
                    "rangebench.cli.run_attempt",
                    return_value=result,
                ) as run_attempt,
                patch("rangebench.cli._get_attacker_digest", return_value="sha256:test"),
            ):
                with self.assertRaises(SystemExit) as caught:
                    cmd_run(args)
            self.assertEqual(caught.exception.code, 1)
            self.assertEqual(run_attempt.call_args.kwargs["attacker_image"], "sha256:test")
            saved = json.loads((Path(tmp) / "latest.json").read_text())["tasks"][0]
            self.assertFalse(saved["scored"])
            self.assertEqual((saved["input_tokens"], saved["output_tokens"]), (120, 45))
            self.assertEqual(saved["cache_read_tokens"], 60)
            self.assertEqual(saved["compaction_cache_read_tokens"], 0)
            self.assertIsNone(saved["cache_write_tokens"])
            self.assertEqual(saved["cache_read_reported_calls"], 2)
            manifest = next(Path(tmp).glob("*/manifest.json"))
            self.assertEqual(json.loads(manifest.read_text())["status"], "completed_with_errors")

    def test_preflight_stops_if_attacker_build_fails(self) -> None:
        with (
            patch("shutil.which", return_value="/usr/bin/docker"),
            patch("rangebench.cli.subprocess.run") as run,
        ):
            run.side_effect = [
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "Docker Compose version 2", ""),
                subprocess.CalledProcessError(1, "docker build"),
            ]
            with self.assertRaises(subprocess.CalledProcessError):
                cmd_preflight(argparse.Namespace())
            self.assertEqual(run.call_count, 3)
            self.assertIn("attacker", str(run.call_args.args[0]))

    def test_git_commit_is_read_from_benchmark_checkout(self) -> None:
        with patch("rangebench.cli.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "deadbeef\n", "")
            self.assertEqual(_get_git_commit(), "deadbeef")
            self.assertEqual(run.call_args.kwargs["cwd"], Path(__file__).resolve().parents[1])


if __name__ == "__main__":
    unittest.main()
