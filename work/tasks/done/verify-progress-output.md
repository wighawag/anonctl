---
title: verify (and use) should show progress while probing - it currently prints nothing for several seconds
slug: verify-progress-output
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [15, 18]
---

## What to build

`anonctl verify` runs several live probes (each a real connection through the shim; the exit-IP check dials Tor) and currently BUFFERS the whole Report, then prints all PASS/FAIL lines at once (`verify.Run` collects all assertions, then `runVerify` prints `rep.Human()`). So the operator sees NOTHING for several seconds, then the full block appears. Add progress feedback so it is visibly working.

- **Stream per-assertion progress**: as each check RUNS, emit a progress line (e.g. `  ... anonymized-exit`), and print each `[PASS]/[FAIL]` result AS IT COMPLETES rather than buffering the whole report. So the operator sees the lines appear one by one, learns which probe is slow, and knows it is alive. The final set of PASS/FAIL lines + exit code is unchanged.
- **Where it lives (so `use` gets it too):** `anonctl use` runs the SAME verify as its gate. Put the progress emission in the shared verify path (a per-check callback on `verify.Run`, or a streaming variant both `runVerify` and `use` call), NOT only in `runVerify`, so `use`'s pre-shell verify shows the same progress.
- **Progress goes to STDERR (or is suppressed), never stdout:** under `--json`, stdout MUST stay pure JSON (a tool parses it), so progress output is SUPPRESSED entirely under `--json`. In the human path, progress may go to stderr (leaving the PASS/FAIL result lines on stdout as today) OR be interleaved on stdout - pick one, but `--json` must emit ONLY the JSON blob on stdout with no progress noise.
- Keep it simple: a per-check "running <name>" + the streamed result is enough; no fancy spinner needed (though a minimal in-place spinner/`...` is fine if it degrades cleanly on a non-tty, i.e. no spinner when output is not a terminal).

## Acceptance criteria

- [ ] `anonctl verify` (human, non-JSON) shows progress as it runs: a per-check indication and each PASS/FAIL streamed as it completes, so there is visible activity during the multi-second run (not a silent wait then a dump).
- [ ] `anonctl use` shows the SAME progress during its gating verify (the progress lives in the shared verify path, not only runVerify).
- [ ] `anonctl verify --json` emits ONLY the JSON report on stdout - NO progress lines, no spinner, nothing else (the machine contract is untouched); progress is suppressed under --json.
- [ ] Progress degrades cleanly on a non-tty (piped/redirected): no spinner control chars in a redirected stream; a plain per-line progress or nothing, never garbage.
- [ ] The final assertion set, ordering, exit code, and JSON are identical to today.
- [ ] Tests cover: the human path streams/emits progress (assert via the injectable writer/seam), the --json path emits no progress (stdout is pure JSON), and use's verify path also emits progress.

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make `anonctl verify` (and `use`'s gating verify) show it is working during the multi-second probe run, instead of printing nothing then dumping the whole report. Maintainer request.
>
> FIRST, read `internal/verify/verify.go` `Run` (collects all assertions then returns; `Report.Human()` renders them all at once) and `main.go` `runVerify` (`if cmd.JSON { stdout=JSON } else { fmt.Print(rep.Human()) }`) and the `use` verb (it runs the same verify as its gate - find where, so progress lives in the SHARED path and `use` gets it for free).
>
> Add a per-check progress hook to verify.Run (e.g. an optional callback invoked before/after each Check) or a streaming Run variant; in the human path emit a per-check progress line + the streamed PASS/FAIL result; under --json emit NOTHING but the JSON on stdout (progress suppressed). Progress to stderr (keep result lines where they are) or interleaved - your call, but --json stdout stays pure JSON. Degrade on non-tty (no control chars when not a terminal).
>
> Where to test: assert the human path emits progress and the --json path does not (inject the progress writer / a tty flag so the unit test drives both without a real terminal); assert use's verify path emits progress too. "Done" = verify and use visibly show activity while probing, --json is untouched, non-tty is clean.
