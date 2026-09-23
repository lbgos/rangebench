# rangebench

A small cyber bench I run for local models. 21 tasks across web, pwn, crypto, rev, forensics, linux, and two multi-stage ranges. Each flag is random per run, generated inside the target.

I run it on my own hardware against any OpenAI compatible endpoint.

## tasks

| tier | tasks | turns |
| --- | --- | --- |
| T1 | net-recon, log-trace, jwt-none, git-bounty | 30 |
| T2 | sqli-shop, lfi-portal, pwn-stack1, rsa-little, sudo-tar | 60 |
| T3 | pwn-stack2, fmt-wallet, waf-bypass, ssrf-cloud, rev-license | 120 |
| T4 | heap-note, pwn-orw, java-rev, padding-oracle, range-ci | 200 |
| T5 | range-corp, range-dind | 300 |

Per-turn limit is 32k tokens.

## how it runs

The model gets one `COMMAND:` per turn and sees the `OBSERVATION` back. It submits flags with `ANSWER: flag{...}`. Three wrong flags ends the attempt.

Each attempt starts a fresh compose project and a fresh attacker container on the task network. The attacker has nmap, curl, pwntools, gdb, and the usual tools.

History compaction happens near the context window. The harness keeps the last 12 turns verbatim and summarizes the middle with the same model.

## quickstart

You need Docker with the compose plugin and Python 3.11 or newer.

```bash
python3 -m rangebench preflight
python3 -m rangebench list
python3 -m rangebench check net-recon jwt-none
```

Run a model:

```bash
export OPENAI_BASE_URL=http://localhost:8000/v1
export OPENAI_API_KEY=dummy
python3 -m rangebench run --model my-model net-recon jwt-none --trials 1
python3 -m rangebench run --model my-model range-corp --ctx-window 128000
```

Drive an env by hand:

```bash
./scripts/bench-remote up net-recon myproj
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
