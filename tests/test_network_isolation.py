import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from rangebench.env import EnvError, Task, TaskEnv


class NetworkIsolationTests(unittest.TestCase):
    def test_external_task_network_is_rejected(self) -> None:
        task = Task("sample", Path("/tmp"), "web", 1, "Find the flag")
        env = TaskEnv(task, "rb-test")
        responses = [
            subprocess.CompletedProcess([], 0, "rb-test_default\nrb-test_core\n", ""),
            subprocess.CompletedProcess([], 0, "false\n", ""),
        ]
        with patch("rangebench.env._run", side_effect=responses):
            with self.assertRaisesRegex(EnvError, "allows external access"):
                env.verify_isolation(["rb-test_default"])


if __name__ == "__main__":
    unittest.main()
