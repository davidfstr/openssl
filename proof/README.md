# Formal proofs (`proof/`)

Machine-checked proofs about OpenSSL source code, run in CI against a pinned
toolchain. Today this is one proof: a Frama-C/WP deductive verification of the
Punycode decoder. The directory is structured so more proofs can be added beside
it without disturbing the build (`proof/` is not in any `build.info` `SUBDIRS`
list, so the normal build ignores it entirely).

```
proof/
  run_proofs.pl        single entrypoint: runs every proof in the pinned container
  docker/Dockerfile    pinned Frama-C + Alt-Ergo + Z3 + cvc5 toolchain
  punycode/
    run_wp.sh          the punycode WP runner (prove | report | check-scope)
    wp-cache/          committed WP proof cache (CI replays it; see below)
```

## Running

```sh
./proof/run_proofs.pl              # all proofs, inside the pinned Docker toolchain
./proof/run_proofs.pl --no-docker  # use a local Frama-C install instead
```

Exit status is 0 iff every proof passes. The per-proof runner can also be driven
directly (needs a local Frama-C 31.0 with Alt-Ergo, Z3, cvc5 on `PATH`):

```sh
./proof/punycode/run_wp.sh prove        # the proof (per-VC results)
./proof/punycode/run_wp.sh report       # source-located scoreboard of any non-Valid goal
./proof/punycode/run_wp.sh check-scope  # verify the proved-function allowlist is current
```

## The Punycode proof

Frama-C's WP plugin proves `ossl_punycode_decode()` (and its helpers `adapt`,
`is_basic`, `digit_decoded`) in `crypto/punycode.c` against ACSL contracts
written **inline in that source file** as `/*@ ... */` comments. WP is modular
deductive verification: it discharges the obligations once, symbolically, for
**all** inputs and buffer sizes -- no test vectors, no fuzzing, no bounded model.

**Result: 104 / 104 goals proved in scope.** Every obligation in
`ossl_punycode_decode` is discharged -- all memory safety (array bounds, the
`memmove` region, and the CVE-2022-3602 scalar write `pDecoded[i]`), all
division-by-zero, and full termination of all four loops and of `adapt`'s loop.
Goals are closed by Qed + Alt-Ergo, with Z3 and cvc5 kept in the portfolio
because no single solver proves everything (see the `run_wp.sh` header).

The proof was developed step-by-step; the full per-step reasoning for every flag
lives in the header comment of `punycode/run_wp.sh`.

### What the proof assumes (trust base + caller obligations)

The result is "proven clean" *modulo* these, and any honest claim must state them:

1. **libc `memmove` byte/element equivalence** (trust base -- assumed, not proved).
   WP's Typed memory model cannot relate the library `memmove`'s byte-wise
   contract (`(char*)dest`, `n` bytes) to the `unsigned int`-typed buffer across
   the type partition. The `-instantiate` plugin rewrites the call to an
   element-wise `memmove_uint`, which lets the call-site obligations prove but
   leaves `memmove_uint`'s own typed `assigns` clause `[Unknown]`. That residue
   *is* the assumption, confined to one generated stub: **"a libc `memmove` of
   `4k` bytes behaves as an element-wise move of `k` `uint32`s."**

2. **Caller obligations** (the `requires` clauses -- discharged onto callers):
   - `\valid_read(pEncoded + (0 .. enc_len-1))`, `\valid(pout_length)`,
     `\valid(pDecoded + (0 .. *pout_length-1))` -- the buffers are as described.
   - `enc_len <= UINT_MAX` -- needed for loop termination (the loop counters are
     `unsigned int`). Upstream now enforces this at runtime with an explicit
     `if (enc_len >= UINT_MAX) return 0;` guard at the top of the function.
   - `*pout_length < UINT_MAX` -- **excludes a latent division-by-zero.** If
     `*pout_length == UINT_MAX` were allowed, `written_out + 1` (passed as
     `adapt`'s `unsigned int numpoints`) could wrap to 0, dividing by zero in
     `adapt`. Unreachable from any sane caller (it needs a ~4-billion-char label;
     DNS labels are <= 63 chars), but the function *in isolation* permits it, and
     sound verification surfaced it. This one is **not** yet guarded upstream.

### Scope honesty

This proof covers `ossl_punycode_decode` **only** -- not `ossl_a2ulabel`, the
`WPACKET`-based caller that actually held CVE-2022-3786. Decode is the tractable
island; the CI gate does not verify the caller, so read no more assurance into a
green check than the above states. The `check-scope` mode is a drift guard: it
fails if any function reachable from `ossl_punycode_decode` and defined in-tree
falls outside the proved allowlist (where WP would silently *assume* its contract
rather than check it).

## Contact

If a change you are making breaks the WP proof in CI and you cannot work out how
to fix the annotations, the proof's point of contact is **David Foster**
(@davidfstr, david AT dafoster DOT net) -- reach out and I will help.
