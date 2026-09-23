import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from rangebench.agent import Usage
from rangebench.cli import _get_task_set_hash
from rangebench.env import EnvError, _run


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


if __name__ == "__main__":
    unittest.main()
