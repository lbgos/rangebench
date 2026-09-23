"""Context compaction invariants independent of Docker or a live model."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from rangebench.agent import Usage
from rangebench.runner import (
    DEFAULT_CTX_WINDOW,
    MAX_CTX_WINDOW,
    AttemptResult,
    _compact_history_llm,
    _deterministic_trim,
    _estimate_tokens,
    _maybe_compact,
    _request_max_tokens,
    _split_history,
    run_attempt,
)


def history(turns: int, observation: str = "observed") -> list[dict]:
    messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "Capture two flags"},
    ]
    for n in range(turns):
        messages.extend(
            [
                {"role": "assistant", "content": f"COMMAND:\nprobe {n}"},
                {"role": "user", "content": f"OBSERVATION {n}: {observation}"},
            ]
        )
    return messages


class FakeClient:
    def __init__(self, answer: str = "port 8080 is open", error: str | None = None):
        self.answer = answer
        self.error = error
        self.calls: list[list[dict]] = []
        self.limits: list[int] = []

    def chat(
        self, messages: list[dict], max_tokens: int, temperature: float = 0.2
    ) -> tuple[str, Usage, str | None]:
        self.calls.append(messages)
        self.limits.append(max_tokens)
        usage = Usage(prompt_tokens=90, completion_tokens=20, reasoning_tokens=10)
        return self.answer, usage, self.error


class CompactionTests(unittest.TestCase):
    def test_tail_counts_agent_turns_and_preserves_feedback(self) -> None:
        messages = history(20)
        head, middle, tail = _split_history(messages, 12)
        self.assertEqual(head, messages[:2])
        self.assertEqual(len(middle), 16)
        self.assertEqual(tail, messages[18:])
        self.assertEqual(sum(m["role"] == "assistant" for m in tail), 12)

    def test_cumulative_attempt_usage_does_not_force_compaction(self) -> None:
        messages = history(5)
        events: list[str] = []
        result = AttemptResult("test", 1, prompt_tokens=1_000_000)
        new = _maybe_compact(
            FakeClient(),
            messages,
            result,
            5000,
            1000,
            2,
            0.8,
            False,
            lambda kind, **kwargs: events.append(kind),
        )
        self.assertIs(new, messages)
        self.assertEqual(events, [])

    def test_provider_usage_calibrates_next_request(self) -> None:
        messages = history(6, "x" * 100)
        events: list[str] = []
        estimated = _estimate_tokens(messages)
        new = _maybe_compact(
            FakeClient(),
            messages,
            AttemptResult("test", 1),
            1800,
            200,
            2,
            0.8,
            False,
            lambda kind, **kwargs: events.append(kind),
            previous_prompt_tokens=1500,
            previous_estimate=estimated,
        )
        self.assertLess(len(new), len(messages))
        self.assertIn("compaction", events)

    def test_reserve_triggers_compaction_before_threshold(self) -> None:
        messages = history(10, "x" * 1400)
        estimated = _estimate_tokens(messages)
        self.assertLess(estimated, 4000)
        events: list[str] = []
        compacted = _maybe_compact(
            FakeClient(),
            messages,
            AttemptResult("test", 1),
            5000,
            2000,
            2,
            0.9,
            False,
            lambda kind, **kwargs: events.append(kind),
        )
        self.assertIn("compaction", events)
        self.assertLess(_estimate_tokens(compacted), 3750)

    def test_large_early_history_reduces_tail_to_fit(self) -> None:
        messages = history(8, "x" * 3500)
        events: list[str] = []
        compacted = _maybe_compact(
            FakeClient(),
            messages,
            AttemptResult("test", 1),
            8000,
            1000,
            12,
            0.82,
            False,
            lambda kind, **kwargs: events.append(kind),
        )
        self.assertIn("compaction", events)
        self.assertLess(_estimate_tokens(compacted), 6000)
        self.assertEqual(compacted[-2:], messages[-2:])

    def test_small_context_caps_generation_without_disabling_compaction(self) -> None:
        messages = history(20, "x" * 3000)
        events: list[str] = []
        compacted = _maybe_compact(
            FakeClient(),
            messages,
            AttemptResult("test", 1),
            16000,
            12000,
            12,
            0.82,
            False,
            lambda kind, **kwargs: events.append(kind),
        )
        self.assertIn("compaction", events)
        requested = _request_max_tokens(compacted, 16000, 32768, 0, 0)
        self.assertGreater(requested, 0)
        self.assertLess(requested, 32768)
        self.assertLessEqual(requested + _estimate_tokens(compacted), 16000)

    def test_global_context_ceiling_overrides_larger_configured_window(self) -> None:
        self.assertEqual(DEFAULT_CTX_WINDOW, MAX_CTX_WINDOW)
        self.assertEqual(MAX_CTX_WINDOW, 258000)
        messages = history(200, "x" * 4500)
        events: list[str] = []
        compacted = _maybe_compact(
            FakeClient(),
            messages,
            AttemptResult("test", 1),
            1_000_000,
            12000,
            12,
            0.82,
            False,
            lambda kind, **kwargs: events.append(kind),
        )
        self.assertIn("compaction", events)
        self.assertLess(len(compacted), len(messages))
        requested = _request_max_tokens(messages, 1_000_000, 1_000_000, 0, 0)
        self.assertLessEqual(requested + _estimate_tokens(messages), MAX_CTX_WINDOW)

    def test_smaller_model_window_triggers_before_global_ceiling(self) -> None:
        messages = history(20, "x" * 6000)
        self.assertLess(_estimate_tokens(messages), int(MAX_CTX_WINDOW * 0.82))
        full = _maybe_compact(
            FakeClient(),
            messages,
            AttemptResult("test", 1),
            MAX_CTX_WINDOW,
            12000,
            12,
            0.82,
            False,
            lambda kind, **kwargs: None,
        )
        small = _maybe_compact(
            FakeClient(),
            messages,
            AttemptResult("test", 1),
            32000,
            12000,
            12,
            0.82,
            False,
            lambda kind, **kwargs: None,
        )
        self.assertIs(full, messages)
        self.assertLess(len(small), len(messages))

    def test_llm_reads_full_history_and_preserves_recent_turns(self) -> None:
        messages = history(15, "x" * 4000 + "TAIL_MARKER")
        client = FakeClient("Known fact: stage one captured")
        compacted, tokens, error = _compact_history_llm(client, messages, 12)
        self.assertIsNone(error)
        self.assertEqual(tokens, 110)
        self.assertIn("Capture two flags", client.calls[0][1]["content"])
        self.assertIn("TAIL_MARKER", client.calls[0][1]["content"])
        self.assertIn("stage one captured", compacted[2]["content"])
        self.assertEqual(compacted[3:], messages[-24:])

    def test_llm_summary_input_is_bounded_and_retains_prior_memory(self) -> None:
        messages = history(20, "x" * 3000)
        messages.insert(2, {"role": "user", "content": "[COMPACTION MEMORY]\nPRIOR_FACT=host42"})
        messages[6]["content"] = "Correct, stage 'web' captured."
        messages[-5]["content"] += " RECENT_MIDDLE=service23"
        client = FakeClient()
        _compact_history_llm(client, messages, 2, ctx_window=8000, token_density=2.0)
        source = client.calls[0][1]["content"]
        self.assertIn("PRIOR_FACT=host42", source)
        self.assertIn("stage 'web' captured", source)
        self.assertIn("RECENT_MIDDLE=service23", source)
        self.assertIn("older messages omitted", source)
        self.assertLess(_estimate_tokens(client.calls[0]) * 2 + client.limits[0], 8000)

    def test_run_attempt_passes_context_capped_generation_limit(self) -> None:
        class FakeEnv:
            def __init__(self, task: object, project: str) -> None:
                pass

            def up(self) -> None:
                pass

            def down(self) -> tuple[bool, None]:
                return True, None

        task = SimpleNamespace(
            id="context-cap",
            statement="A small task",
            stages=[],
            turns=1,
            infra_timeout=5,
            max_tokens=32768,
            max_output_tokens=100000,
            canary="",
        )
        client = FakeClient("COMMAND:\ntrue")
        with TemporaryDirectory() as directory, patch("rangebench.runner.TaskEnv", FakeEnv):
            run_attempt(client, task, 1, "test", Path(directory), verbose=False, ctx_window=16000)
        self.assertEqual(len(client.limits), 1)
        self.assertGreater(client.limits[0], 0)
        self.assertLess(client.limits[0], task.max_tokens)

    def test_failed_summary_counts_usage_and_keeps_deterministic_memory(self) -> None:
        messages = history(8, "service 8080 open " + "x" * 500)
        result = AttemptResult("test", 1)
        events: list[str] = []
        compacted = _maybe_compact(
            FakeClient("", "provider error"),
            messages,
            result,
            1200,
            200,
            2,
            0.8,
            True,
            lambda kind, **kwargs: events.append(kind),
        )
        self.assertEqual(result.compaction_tokens, 110)
        self.assertIn("compaction-fallback", events)
        self.assertIn("service 8080 open", compacted[2]["content"])

    def test_second_compaction_retains_old_memory_and_new_feedback(self) -> None:
        first = _deterministic_trim(history(8, "port 8080 open"), 2)
        first.extend(
            [
                {"role": "assistant", "content": "COMMAND:\ncat /work/notes"},
                {"role": "user", "content": "Correct, stage 'web' captured."},
                {"role": "assistant", "content": "COMMAND:\nprobe again"},
                {"role": "user", "content": "Remaining stage: root"},
            ]
        )
        second = _deterministic_trim(first, 1)
        self.assertIn("port 8080 open", second[2]["content"])
        self.assertIn("stage 'web' captured", second[2]["content"])
        self.assertEqual(second[-2:], first[-2:])


if __name__ == "__main__":
    unittest.main()
