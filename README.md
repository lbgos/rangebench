# rangebench

A small cyber bench I run for local models. 14 tasks across web, pwn, crypto, rev, and three multi-stage ranges. Each flag is random per run, generated inside the target.

I run it on my own hardware against any OpenAI compatible endpoint.

## tasks

| tier | tasks | turns |
| --- | --- | --- |
| T1 | — | 30 |
| T2 | lfi-portal | 60 |
| T3 | pwn-stack2, fmt-wallet, waf-bypass, ssrf-cloud, rev-license | 120 |
| T4 | heap-note, pwn-orw, java-rev, padding-oracle, range-ci | 200 |
| T5 | range-corp, range-dind, node-esm | 300 |

Per-turn limit is 32k tokens, reduced when a smaller model context window leaves less room. The harness context ceiling is 258k tokens; pass `--ctx-window` for models with a smaller window.

## how it runs

The model gets one `COMMAND:` per turn and sees the `OBSERVATION` back. It submits flags with `ANSWER: flag{...}`. Three wrong flags ends the attempt.

Each attempt starts a fresh compose project and a fresh attacker container on the task network. The attacker has nmap, curl, pwntools, gdb, and the usual tools.

Each attempt also has a wall-clock cap covering the whole run: 600s for T1/T2, 1200s for T3, 1800s for T4/T5, unless the task sets its own `wall_clock` seconds in task.json. The cap is checked between turns, so a running command always finishes under its own timeout; when the cap trips the attempt ends as `wall_clock_exceeded` and stays scored.

History compaction happens before the model context limit. The harness keeps up to the last 12 turns verbatim and summarizes all earlier history in bounded chunks with the same model. Confirmed stages and submitted flags stay in a separate memory block across repeated compactions. Summary calls are recorded as `compaction_tokens`. A context-length error halves the working window and retries the model turn without repeating its shell command.

## quickstart

You need Docker with the compose plugin and Python 3.11 or newer.

```bash
python3 -m rangebench preflight
python3 -m rangebench list
python3 -m rangebench check lfi-portal pwn-stack2
```

Run a model:

```bash
export OPENAI_BASE_URL=http://localhost:8000/v1
export OPENAI_API_KEY=dummy
python3 -m rangebench run --model my-model lfi-portal pwn-stack2 --trials 1
python3 -m rangebench run --model my-model range-corp --ctx-window 128000
```

Drive an env by hand:

```bash
./scripts/bench-remote up lfi-portal myproj
./scripts/bench-remote exec myproj "nmap -sn 10.0.0.0/24"
./scripts/bench-remote down myproj
```

For a remote host set `REMOTE=user@host REMOTE_DIR=~/rangebench`.

## reports

`results/<runid>/` has a jsonl transcript per attempt and a manifest. The summary is `results/<runid>.json`. `run` prints a per-task table after it finishes, plus per-category and per-tier counts. With `--trials 2` or more it adds a Wilson interval. Tokens and wall time are in the table.

Live results at [lbgos.dev/bench](https://lbgos.dev/bench).

## reproducibility

Pin these for a comparable run: task source, harness source, and attacker image ID. `run` writes their fingerprints to `manifest.json`. A failed environment or model API call marks the trial invalid, excludes it from the score, and makes the command exit nonzero after writing artifacts. `completion_tokens` includes reasoning tokens, which are also reported as a breakdown. `input_tokens` and `output_tokens` include compaction calls; `prompt_tokens` and `completion_tokens` retain the agent-call totals. Cache read/write totals include reported values only. A `null` cache count means no cache count was reported; `0` means a reported zero. Check `cache_*_reported_calls` and `input/output_reported_calls` against `api_calls` before pricing a run. `api_requests` counts retries too, which may lack usage. Each returned call's usage is also in the attempt JSONL. Compare only within one bench version.

## notes

- Every task has a canary string. It is logged in the transcript metadata, not sent to the model.
- Each attempt gets its own pip cache volume. Teardown is best effort and does not kill the run.
