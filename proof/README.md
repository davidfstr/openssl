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
    wp-cache/          committed WP proof cache (CI --load replays it; see below)
```

## Running

`run_proofs.pl` has three workflows that differ only in how they use the
committed WP proof cache:

```sh
./proof/run_proofs.pl              # (default) PROVE locally: race the solvers,
                                   #   cache to a gitignored scratch dir. Fast;
                                   #   for a human iterating on the proof.
./proof/run_proofs.pl --load       # USE the committed cache only, no solver runs;
                                   #   fail on any miss. Deterministic; CI uses this.
./proof/run_proofs.pl --save       # REGENERATE the committed cache from scratch,
                                   #   deterministically (must run in Docker); commit it.
./proof/run_proofs.pl --no-docker  # any of the above against a local Frama-C
                                   #   (not allowed with --save)
```

Exit status is 0 iff every proof passes. Note Frama-C itself exits 0 even with
unproved goals, so the runner gates explicitly on `Proved goals: N / M` (`N == M`);
under `--load` a cache miss leaves goals unproved and thus fails, which is exactly
how a stale committed cache is detected — regenerate it with `--save`.

**Updating the committed cache.** Regenerate (`--save`) after any change that
alters the proof obligations — the C code or its ACSL annotations, a Frama-C or
solver version bump in the Dockerfile, or an obligation-affecting flag in
`run_wp.sh` — then commit `proof/*/wp-cache/`. There is no mtime heuristic: the
cache is content-addressed (keyed on the goal formula + solver version), so
`--load` detecting a miss *is* the staleness check. `--save` runs one prover at a
time in a fixed order so the winning solver per goal — and hence the cache — is
identical on every machine (an 8-way race would make it host-specific).

The per-proof runner can also be driven directly (needs a local Frama-C 31.0 with
Alt-Ergo, Z3, cvc5 on `PATH`):

```sh
./proof/punycode/run_wp.sh prove        # the proof (per-VC results)
./proof/punycode/run_wp.sh report       # source-located scoreboard of any non-Valid goal
./proof/punycode/run_wp.sh check-scope  # verify the proved-function allowlist is current
```

## The Punycode proof

Frama-C's WP plugin proves `ossl_a2ulabel()` -- and its entire in-tree call tree
(`codepoint2utf8`, `ossl_punycode_decode`, `adapt`, `is_basic`, `digit_decoded`,
`ossl_assert_int`) -- in `crypto/punycode.c` against ACSL contracts written
**inline in that source file** as `/*@ ... */` comments. WP is modular deductive
verification: it discharges the obligations once, symbolically, for **all**
inputs and buffer sizes -- no test vectors, no fuzzing, no bounded model.

**Result: 311 / 311 goals proved in scope.** Every obligation across the tree is
discharged -- all memory safety (array bounds, the `memmove` region, the
CVE-2022-3602 scalar write `pDecoded[i]`, and the `WPACKET` bump-pointer writes
into `out` that bound the CVE-2022-3786 class), all division-by-zero, and full
termination of every loop. Goals are closed by Qed + Alt-Ergo, with Z3 and cvc5
kept in the portfolio because no single solver proves everything (see the
`run_wp.sh` header). An earlier revision proved only the `ossl_punycode_decode`
"island"; the proof now covers the outer entrypoint and everything it reaches.

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

2. **`WPACKET` contracts** (trust base -- assumed, not proved). `ossl_a2ulabel`
   writes its output through `WPACKET_init_static_len` / `WPACKET_memcpy` /
   `WPACKET_put_bytes__` / `WPACKET_cleanup`, whose bodies live in
   `crypto/packet.c`, outside this proof's translation unit. Their ACSL contracts
   are supplied by `proof/punycode/wpacket_spec.h` (force-included via
   `-include`) and **assumed** -- WP checks `ossl_a2ulabel` against them but never
   checks them against `packet.c`. They are scoped to exactly how `ossl_a2ulabel`
   drives a fixed-buffer, no-length-prefix, forward-only `WPACKET` (captured by
   the `wpacket_static_inv` predicate), and each `assigns`/`requires` range is
   clipped to `min(written + len, maxsize)` to match `packet.c`'s own
   reserve-then-write behaviour. That header must be re-audited by hand against
   `packet.c` whenever the `WPACKET` implementation changes -- see its header
   comment for the per-clause derivation.

3. **Caller obligations of `ossl_a2ulabel`** (the outer `requires` -- discharged
   onto whoever calls it):
   - `valid_read_string(in)` -- `in` is a NUL-terminated readable string.
   - `strlen(in) <= PTRDIFF_MAX` -- needed for the `tmpptr - inptr` pointer
     subtraction and the `size_t` cast of the label length.
   - `\valid(out + (0 .. outlen-1))` and `\separated(in .. , out .. )` -- the
     output buffer is writable and does not overlap the input.

   The `ossl_punycode_decode` `requires` from the earlier island proof are now
   **internal**, discharged by `ossl_a2ulabel` at the call site rather than by an
   external caller: it passes a 512-element `buf` (`bufsize = LABEL_BUF_SIZE`), so
   `enc_len <= UINT_MAX` (the label length is bounded by the input) and
   `*pout_length < UINT_MAX` (512) both hold. In particular the latent
   division-by-zero that sound verification surfaced in decode *in isolation*
   (reachable only with `*pout_length == UINT_MAX`, a ~4-billion-element output
   buffer) is now **proved unreachable through this caller** -- `ossl_a2ulabel`
   never offers decode a buffer that large.

### Scope

This proof covers `ossl_a2ulabel` and its full in-tree call tree, including
`ossl_punycode_decode` -- the caller that held CVE-2022-3786 and the decoder that
held CVE-2022-3602, respectively. The remaining assurance gap is the trust base
above (WPACKET + `memmove` contracts), not an unproved caller. The `check-scope`
mode is a drift guard with two parts: (a) it fails if any function reachable from
`ossl_a2ulabel` and defined in-tree falls outside the proved allowlist (where WP
would silently *assume* its contract rather than check it); and (b) a MUST_COVER
floor fails loudly if either committed entrypoint -- `ossl_a2ulabel` or
`ossl_punycode_decode` -- ever stops being reachable from the root, so a refactor
can never silently retire their guarantee.

## Contact

If a change you are making breaks the WP proof in CI and you cannot work out how
to fix the annotations, the proof's point of contact is **David Foster**
(@davidfstr, david AT dafoster DOT net) -- reach out and I will help.
