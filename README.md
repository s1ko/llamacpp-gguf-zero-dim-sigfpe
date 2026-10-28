# llama.cpp / ggml: division by zero in the GGUF loader when a tensor dimension is zero

`gguf_init_from_reader` in `ggml/src/gguf.cpp` rejects negative tensor dimensions
but not zero ones, and then divides `INT64_MAX` by `ne[1]`, `ne[2]` and `ne[3]` to
check that the element count is representable. A GGUF file with a tensor whose
`n_dims >= 2` and a zero dimension past the first makes that division raise
`#DE` on x86-64, so the process dies with SIGFPE before it has allocated anything.
A 53-byte file is enough, and every program that opens a GGUF through ggml —
`llama-cli`, `llama-server`, language bindings, vendored copies — terminates when it
opens one. The bug is fixed upstream. It is not a first report: the same crash was
proposed for fixing in public on 2026-01-04 (see [Prior coverage](#prior-coverage)).

| | |
|---|---|
| CVE | none |
| CWE | CWE-369 (Divide By Zero) |
| Project | [`ggml-org/llama.cpp`](https://github.com/ggml-org/llama.cpp), `ggml/src/gguf.cpp` (also any project vendoring ggml's `gguf.cpp`) |
| Affected | tags b4437 (2025-01-08, the GGUF C++ refactor `53ff6b9b9`) through b10380 (2026-08-11) |
| Fixed in | `d8a8beac22` (#25596, 2026-08-12), first tag b10398; guard reworked in `2149c00f44` (#29384, 2026-09-30), first tag b11301. b11968 (2026-10-28) is clean |
| CVSS v3.1 | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` = **5.5 Medium**; `AV:N/UI:N` = 7.5 only where a service ingests GGUF files from untrusted sources without a user action |
| Reported by | s1ko ([github.com/s1ko](https://github.com/s1ko), `s1ko@riseup.net`) |

## Scope, stated plainly

- **Denial of service only.** The crash is a clean process termination on the first
  division, before any allocation: no memory corruption, no read or write primitive.
- **The victim must open an attacker-supplied model file.** That is a user action
  (downloading a model from a hub, pointing `-m` at a file) or an automated
  pipeline that parses GGUF headers from uploads. The Huntr submission scored this
  `AV:N/UI:N` (7.5) on the premise that `llama-server` is network-reachable; the
  server loads the model it is told to load and this advisory has not shown a path
  by which a remote client names an arbitrary file for it. Hence 5.5 as the base
  score.
- **x86-64 traps, other architectures may not.** Integer division by zero raises
  `#DE` on x86-64. Upstream issue #26366 reports that on arm64 `SDIV` by zero
  yields 0 without trapping, the comparison then fails and the file is rejected.
  This advisory ran x86-64 only.
- **Upstream policy.** `SECURITY.md` states that "Denial-of-Service (DoS) bugs are
  generally not treated as vulnerabilities" and that untrusted models should be run in
  a sandbox. This advisory is filed as a documented robustness bug for that reason; it
  does not argue the policy.
- **Zero-element tensors are legal GGUF.** Upstream review of the fix noted that
  safetensors allows them, that some diffusion models use them as markers, and that
  `gguf-py` reads such a file as shape `[1, 0]`. The fix therefore accepts them
  instead of rejecting the file, as the first suggestion here (`ne <= 0`) would have.
- **Other projects.** `gguf.cpp` is vendored by projects such as whisper.cpp,
  stable-diffusion.cpp, llamafile, koboldcpp and llama-cpp-python (by submodule).
  Their copies carried the same code until updated. Only whisper.cpp was built and
  run by the author (2026-05-01, exit 136); the rest were read at their pinned
  revisions.

## Threat model

GGUF is a distribution format: models are downloaded from public hubs and
mirrors, shared between users, and parsed by tools that inspect metadata. The
parser's input is therefore attacker-influenced, and the loader is the boundary
that is supposed to turn a malformed file into an error rather than an abort.
The harm here is limited to the loader's availability: a tool that opens a
hostile file dies, which matters most for long-running services (model
routers, validation or indexing pipelines, bindings embedded in an application)
and not at all for a one-shot CLI whose user can simply delete the file.

## Execution

Verbatim from `ggml-org/llama.cpp` commit `f53577432541bb9edc1588c4ef45c66bf07e4468`
(2026-04-26), `ggml/src/gguf.cpp:616-641`. Line 623 rejects only `< 0`; line 632
divides:

```cpp
            for (uint32_t j = 0; ok && j < GGML_MAX_DIMS; ++j) {
                info.t.ne[j] = 1;
                if (j < n_dims) {
                    ok = ok && gr.read(info.t.ne[j]);
                }

                // check that all ne are non-negative
                if (info.t.ne[j] < 0) {
                    GGML_LOG_ERROR("%s: tensor '%s' dimension %" PRIu32 " has invalid number of elements: %" PRIi64 " < 0\n",
                        __func__, info.t.name, j, info.t.ne[j]);
                    ok = false;
                    break;
                }
            }

            // check that the total number of elements is representable
            if (ok && ((INT64_MAX/info.t.ne[1] <= info.t.ne[0]) ||
                       (INT64_MAX/info.t.ne[2] <= info.t.ne[0]*info.t.ne[1]) ||
                       (INT64_MAX/info.t.ne[3] <= info.t.ne[0]*info.t.ne[1]*info.t.ne[2]))) {
```

A dimension read from the file overwrites the default `1`. With `n_dims = 2` and
`ne[1] = 0`, the check on line 623 passes (`0 < 0` is false) and `INT64_MAX/info.t.ne[1]`
is `INT64_MAX/0`. If `n_dims` is 1, `ne[1..3]` stay at the default `1` and nothing
happens, so the zero has to be in the second, third or fourth dimension.

The division was introduced by the C++ rewrite of the GGUF code, `53ff6b9b9`
("GGUF: C++ refactor, backend support, misc fixes", #11030, 2025-01-07), first in tag
b4437.

### Reproduction

The file ([`poc/poc_fpe.gguf`](poc/poc_fpe.gguf), 53 bytes, sha256
`8c6c12bd3192019639ef6835108abefebff0c5d75d7345321267c57634e67384`) is the output of
[`poc/gen_poc.py`](poc/gen_poc.py): header, one tensor named `x`, `n_dims = 2`,
`ne = [1, 0]`, and nothing after it. The crash happens while the dimensions are
being validated, before the reader would reach the missing tensor type and offset.
A copy is also on Hugging Face at
[`s1ko/llamacpp-gguf-fpe-poc`](https://huggingface.co/s1ko/llamacpp-gguf-fpe-poc)
(a gated repository; its card lists the same sha256).

```
4747 5546 0300 0000 0100 0000 0000 0000    GGUF, version 3, n_tensors = 1
0000 0000 0000 0000 0100 0000 0000 0000    n_kv = 0, name length = 1
7802 0000 0001 0000 0000 0000 0000 0000    "x", n_dims = 2, ne[0] = 1, ne[1] starts at byte 13
0000 0000 00                               ... ne[1] = 0, end of file
```

[`poc/gen_poc_wellformed.py`](poc/gen_poc_wellformed.py) writes a complete file (type
and offset present, padded) with the dimensions given on the command line, so a
rejection cannot be mistaken for a truncation error.
[`poc/gguf_open.c`](poc/gguf_open.c) is a small caller of
`gguf_init_from_file`. [`poc/run-poc.sh`](poc/run-poc.sh) builds ggml from a
checkout (outside the checkout), compiles the caller and runs four files:

```
git clone https://github.com/ggml-org/llama.cpp
git -C llama.cpp checkout f53577432541bb9edc1588c4ef45c66bf07e4468
bash poc/run-poc.sh llama.cpp
```

Measured on x86-64 on 2026-10-28:

| Checkout | `control_valid` | `truncated_ne1_zero` (the 53-byte file) | `wellformed_ne1_zero` | `wellformed_ne2_zero` |
|---|---|---|---|---|
| `f53577432` (2026-04-26, as reported) | accepted | **exit 136 (SIGFPE)** | **exit 136** | **exit 136** |
| `132753bf4` (parent of the fix) | accepted | **exit 136** | **exit 136** | **exit 136** |
| `ac8e1694d` (tag b11968) | accepted | rejected (truncated file) | accepted | accepted |

Outputs: [`f53577432`](poc/expected-output-f53577432.txt),
[`132753bf4`](poc/expected-output-132753bf4.txt),
[`ac8e1694d`](poc/expected-output-ac8e1694d.txt). On b11968 the 53-byte file is
rejected because it is truncated, not because of the dimension; the two well-formed
zero-dimension files show the guard itself: they are accepted as zero-element tensors.

The report's sanitizer signature, reproduced with the author's libFuzzer harness
[`poc/fuzz_gguf.cpp`](poc/fuzz_gguf.cpp) built against `f53577432` with
`-fsanitize=address,fuzzer` and run on the file
([`poc/expected-output-asan-f53577432.txt`](poc/expected-output-asan-f53577432.txt)):

```
==PID==ERROR: AddressSanitizer: FPE on unknown address 0xADDR (pc ... T0)
    #0 0xADDR in gguf_init_from_file_ptr llama.cpp/ggml/src/gguf.cpp:632:34
    #1 0xADDR in LLVMFuzzerTestOneInput poc/fuzz_gguf.cpp:39:36
SUMMARY: AddressSanitizer: FPE llama.cpp/ggml/src/gguf.cpp:632:34 in gguf_init_from_file_ptr
```

## Detection

Static check of a GGUF file. [`poc/check_gguf_zero_dim.py`](poc/check_gguf_zero_dim.py)
walks the header and metadata and reports tensors whose dimensions past the first
include a zero. It exits 1 on a finding, 0 when clean, 2 on a parse error:

```
python3 -I poc/check_gguf_zero_dim.py model.gguf
poc/poc_fpe.gguf: tensor 'x' ne=[1, 0] has a zero dimension past ne[0]
```

Run on the 53-byte file and four generated ones, it flagged the 53-byte file and the
two well-formed files with a zero past `ne[0]` (`1 0` and `1 1 0`) and passed the
valid control (`4 3`) and a `ne = [0]` file (which does not crash). A hit is a file that crashes unpatched builds; it is not necessarily
malicious, since zero-element tensors are legal and exist in some real models.

Host telemetry on x86-64 Linux, observed when running the PoC. The kernel logs the
trap:

```
traps: <process>[<pid>] trap divide error ip:<addr> sp:<addr> error:0 in libggml-base.so.<ver>[<offset>,<base>+<size>]
```

and the shell reports `Floating point exception` / exit status 136. A Sigma rule for
the kernel line:

```yaml
title: Divide error trap inside the ggml library
id: 0b1f4ee5-7d3a-4e62-9a43-1f6d4a7c2e90
status: experimental
description: A process faulted with a divide error inside libggml, the signature of the zero-dimension GGUF crash on unpatched x86-64 builds. Also fires for other division faults in ggml.
author: s1ko
date: 2026-10-28
logsource:
  product: linux
  service: kernel
detection:
  selection:
    Message|contains|all:
      - 'trap divide error'
      - 'libggml'
  condition: selection
falsepositives:
  - Other divide-by-zero defects in ggml
level: medium
```

For a statically linked server the module name is the binary, so match on the
binary name as well.

## Mitigation

- **Upgrade to a build at or after b10398** (b11301 or later for the reworked guard).
  Projects that vendor `ggml/src/gguf.cpp` need to take the same change.
- Until then: do not open GGUF files from sources you do not trust with an
  unpatched build; run `check_gguf_zero_dim.py` over incoming files in an ingestion
  pipeline; and run services that load user-supplied models under a supervisor, in a
  container, so a crash is a restart and not an outage.
- A minimal patch for a vendored copy is to skip the representability check when any
  dimension is zero, as `d8a8beac22` does with `ggml_nelements(&info.t) > 0`, rather
  than to reject the file.

NIST SP 800-53r5 `SI-10`; OWASP ASVS v4 §5.1.3; CWE-369 mitigation (check the
divisor before every division); MITRE ATT&CK T1499.004 (Endpoint DoS: Application or
System Exploitation).

## Timeline

| Date | Event |
|---|---|
| 2025-01-07 | The division is introduced by the C++ GGUF refactor (`53ff6b9b9`); first tag b4437 |
| 2026-01-04 | PR [#18586](https://github.com/ggml-org/llama.cpp/pull/18586) by another contributor proposes a zero-dimension guard for this division, citing a private advisory; closed unmerged on 2026-07-14 |
| 2026-01-22 | Issue [#19002](https://github.com/ggml-org/llama.cpp/issues/19002) reports the same division by zero; closed the same day |
| 2026-04-26 | Reported via huntr.com (report `3bda583b-49ec-4926-a65e-acb332d09a70`), verified against `f53577432`. No triage, validation or response from the platform as of 2026-10-28. |
| 2026-07-12 | PR [#25596](https://github.com/ggml-org/llama.cpp/pull/25596) opened with the same finding and a 65-byte PoC |
| 2026-07-21 | A second reproduction is posted on #25596 |
| 2026-07-31 | Issue [#26366](https://github.com/ggml-org/llama.cpp/issues/26366) reports it again, with the arm64/x86-64 difference; closed 2026-09-14 |
| 2026-08-12 | #25596 merged (`d8a8beac22`); first tag b10398 |
| 2026-09-30 | Guard reworked in #29384 (`2149c00f44`); first tag b11301 |
| 2026-10-28 | Published here |

## Prior coverage

This is **not** the first public report of the bug, and this advisory does not claim
first discovery. In order:

1. **PR #18586, 2026-01-04** — "Fix division by zero vulnerability in
   `gguf_init_from_file_impl`": the same unguarded division, with a patch that
   rejects zero dimensions. It cites a private advisory (GHSA-3p75-pq92-q28f, not
   public). Maintainers discussed whether zero-sized tensors should be legal and
   how it should be classified; it was closed unmerged on 2026-07-14.
2. **Issue #19002, 2026-01-22** — the same division at the then-current commit
   (`55abc39355`), closed the same day by its author as already addressed. The code
   at that commit still had the unguarded division, and so did `f53577432` three
   months later.
3. **PR #25596, 2026-07-12** — the merged fix, with a PoC; a reproduction by
   another reporter followed on 2026-07-21.
4. **Issue #26366, 2026-07-31** — the same crash again, noting the x86-64/arm64
   difference.

The report here is dated 2026-04-26, after (1) and (2) and before (3) and (4). It
was made independently, found by fuzzing, and is a duplicate of (1) and (2) in
substance. The fix that landed is the contributor's in #25596, refined by #29384;
nothing in either credits or derives from this report.

## References

- Vulnerable code — https://github.com/ggml-org/llama.cpp/blob/f53577432541bb9edc1588c4ef45c66bf07e4468/ggml/src/gguf.cpp#L616-L641
- Fix — https://github.com/ggml-org/llama.cpp/pull/25596
- Reworked guard — https://github.com/ggml-org/llama.cpp/pull/29384
- Earlier public reports — https://github.com/ggml-org/llama.cpp/pull/18586 , https://github.com/ggml-org/llama.cpp/issues/19002 , https://github.com/ggml-org/llama.cpp/issues/26366
- Upstream policy — https://github.com/ggml-org/llama.cpp/blob/master/SECURITY.md

## License

MIT — see [LICENSE](LICENSE).
