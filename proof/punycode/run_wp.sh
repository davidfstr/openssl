#! /bin/sh
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# run_wp.sh -- Frama-C WP runner for ossl_a2ulabel in crypto/punycode.c.
#
# Deductive verification (Frama-C WP) of ossl_a2ulabel() and its entire in-tree
# call tree -- codepoint2utf8, ossl_punycode_decode, adapt, is_basic,
# digit_decoded, ossl_assert_int -- proved against the ACSL contracts written
# into crypto/punycode.c (and, for the assert helper, internal/common.h). Unlike
# a dynamic or bounded check, WP proves the obligations ONCE, symbolically, for
# all inputs and buffer sizes; it needs no driver harness because it is modular
# deductive verification.
#
# ossl_a2ulabel is the WPACKET-based caller that actually held CVE-2022-3786;
# ossl_punycode_decode (the CVE-2022-3602 locus) is proved as part of the same
# tree. An earlier revision of this script proved ONLY the decode "island"; the
# proof now covers the whole reachable closure from the outer entrypoint. The
# WPACKET functions the caller uses are the one remaining trust base -- their
# bodies live in crypto/packet.c OUTSIDE this TU and are ASSUMED via the
# hand-audited contracts in wpacket_spec.h (see that file and proof/README.md).
#
# Normally invoked via ../run_proofs.pl (which supplies the pinned Docker
# toolchain), but it also runs standalone against a local Frama-C install.
#
# This file doubles as the OPTIONS LOG: every Frama-C/WP flag we adopt is
# recorded here with the reason it was needed, so the evolution of the proof is
# self-documenting. The proof was developed step-by-step in a separate local
# repository (plan/soundness-verification/punycode/wp); that repo's git history
# holds the full per-step annotation progression. The step log below is the
# distilled rationale for the flags this script now uses.
#
# ----------------------------------------------------------------------------
# Why each flag is here (distilled step log):
#
#   -wp-rte     Emit runtime-error guards in addition to the ACSL obligations:
#               array-index validity for pEncoded[..]/pDecoded[..] (the CVE
#               memory-safety class), division-by-zero (divisors w, written_out+1,
#               numpoints), etc. Note unsigned arithmetic emits NO overflow
#               obligation (wraparound is defined in C); the code's own
#               "> (maxint - i)/w" guards are hand-rolled overflow checks, and
#               digit_decoded's signed subtractions are discharged trivially.
#               The real proof task is bounds + nonzero-divisors + termination.
#
#   -wp-prover alt-ergo,z3,cvc5
#               Race all three SMT solvers per goal; the result is the UNION of
#               their strengths. No single solver dominates: e.g. the assert
#               "0 <= i <= written_out" after "i %= (written_out + 1)" needs the
#               mod axiom + size_t->uint truncation + a loop invariant, a
#               multi-theory step Alt-Ergo alone misses but Z3/cvc5 close; yet
#               cvc5 ALONE would lose "loop invariant w >= 1" (the nonlinear
#               w*(base-t) step) that Alt-Ergo and Z3 prove. Never narrow the
#               portfolio to "the newest solver".
#
#   -instantiate
#               Bridge the typed-vs-byte memory-model gap at the memmove call.
#               The library memmove contract is BYTE-wise (valid_or_empty(
#               (char*)dest, n)); WP's default Typed model partitions memory by
#               type, so relating "4*k bytes at (char*)p" to "k uint32 elements
#               at p" is inexpressible and the two memmove preconditions are
#               unprovable BY CONSTRUCTION. -instantiate rewrites the call to a
#               generated element-wise memmove_uint whose contract carries no
#               cast, and the preconditions prove. TRUST-BASE CAVEAT: the gap is
#               RELOCATED, not solved -- memmove_uint's own typed `assigns`
#               clause stays [Unknown], confined to one stub. That residue IS the
#               assumption: "a libc memmove of 4k bytes behaves as an element-wise
#               move of k uint32s." State it in any claim about how proven-correct
#               ossl_punycode_decode() is.
#
#   -wp-model Typed+cast
#               ossl_a2ulabel treats the output buffer as char* (its `out`
#               parameter) and as unsigned char* (the WPACKET staticbuf and the
#               codepoint2utf8 `seed` bytes), relying on those reinterpretations
#               addressing the same storage. WP's default Typed model partitions
#               memory by pointer type, so char*/unsigned char* casts are opaque
#               and the WPACKET_memcpy separation + validity obligations cannot be
#               stated; Typed+cast adds the byte-identity reasoning that closes
#               them. The decode subtree uses no such casts and re-proves unchanged
#               under this model, so ONE model covers the whole scope. (-wp-literals
#               was used during development for the "xn--" strncmp-against-a-literal
#               test; that test was later unrolled into per-char compares, so no
#               string literal remains and the flag was dropped.)
#
#   -cpp-extra-args=-I<repo>/include -include wpacket_spec.h
#               -I<repo>/include: Frama-C preprocesses with -nostdinc and its own
#               libc, so OpenSSL's headers (e_os2.h, crypto/punycode.h,
#               internal/common.h, internal/packet.h, ...) are unfindable without
#               the project include dir. With it the whole translation unit parses;
#               the only residue is benign safestack.h cast warnings, outside our
#               functions.
#               -include wpacket_spec.h: force-include the TRUST-BASE ACSL
#               contracts for the WPACKET functions ossl_a2ulabel calls
#               (WPACKET_init_static_len, _memcpy, _put_bytes__, _cleanup). Their
#               bodies are in crypto/packet.c, outside this TU, so WP ASSUMES these
#               contracts; they are re-audited by hand against packet.c. This is
#               the caller-side counterpart to the memmove_uint residue below.
#
#   -wp-fct ossl_a2ulabel,codepoint2utf8,ossl_punycode_decode,adapt,is_basic,digit_decoded,ossl_assert_int
#               Scope the obligation set to the proof's functions -- the whole
#               in-tree closure reachable from ossl_a2ulabel. WP is modular, so
#               each listed function's body is proved against its own contract and
#               its callees' contracts are assumed; listing the full closure means
#               every in-tree callee's contract is also CHECKED, not merely
#               assumed. The only assumed contracts left are the genuinely
#               out-of-TU ones (WPACKET via wpacket_spec.h, memmove, OPENSSL_die).
#               SCOPE_FCTS below is the single source of truth for this list,
#               shared with the check-scope guard and its MUST_COVER floor.
#
#   -wp-timeout 30
#               Generous per-goal timeout (~15x the time any goal needs on a
#               developer box) so a slow runner never produces a false red
#               "timeout" failure. With the committed proof cache served (offline
#               or replay) goals are discharged without calling a solver at all,
#               so this only bites on a cache miss.
#
#   -wp-par N (FRAMAC_WP_PAR, default 8)
#               Concurrent prover processes. 8 races the portfolio for speed, but
#               then WHICH solver first closes a goal is timing-dependent, so the
#               resulting cache is machine-specific. 1 runs one prover at a time in
#               list order, so the winning prover per goal is capability- (not
#               timing-) determined and identical on every machine -- this is what
#               makes a regenerated cache reproducible. run_proofs.pl uses 8 for
#               local proving and for CI replay (no cache is written on either path,
#               so determinism is moot), and 1 only when regenerating the committed
#               cache (--save), where the winning prover must be reproducible.
#
#   -wp-cache <mode> / -wp-cache-dir <dir> (FRAMAC_WP_CACHE / FRAMAC_WP_CACHEDIR)
#               Serve recorded proofs from a cache dir instead of rediscovering
#               them each run -- the single biggest robustness win against timeout
#               flakiness. See the CACHE section for the modes.
#
# RESULT: 311 / 311 goals proved in scope { ossl_a2ulabel, codepoint2utf8,
# ossl_punycode_decode, adapt, is_basic, digit_decoded, ossl_assert_int }. The
# trust-base residue is TWO stubs: the memmove_uint typed-assigns clause
# described above, and the WPACKET contracts in wpacket_spec.h (assumed, audited
# by hand against crypto/packet.c). Scope covers ossl_a2ulabel -- the
# WPACKET-based caller that actually held CVE-2022-3786 -- and the full tree
# below it, not just the decode island of earlier revisions.
#
# For a source-located view of all obligations, run:  ./run_wp.sh report
# ----------------------------------------------------------------------------
#
# Usage:
#   ./run_wp.sh [prove|report|check-scope]
#
#   prove       -- (default) run WP+RTE, the proof itself. Lists per-VC goal
#                  results with WP-internal names. GATES on completeness: Frama-C
#                  exits 0 even with unproved goals, so this mode parses the
#                  "Proved goals: N / M" summary and exits 1 unless N == M.
#   report      -- the "scoreboard": run WP+RTE, then list every UNPROVEN
#                  obligation as  file:line [status] kind: predicate,  using real
#                  source locations from the Report plugin CSV. A different VIEW
#                  of the same goals (aggregated per property), not joinable with
#                  'prove' by name.
#   check-scope -- DRIFT GUARD for the -wp-fct list: recompute the in-tree
#                  functions reachable from SCOPE_ENTRY and fail (exit 1) if they
#                  differ from the hand-maintained SCOPE_FCTS in either direction.
#                  Run it alongside prove in CI so a new reachable callee cannot
#                  silently fall outside the proven (hence trusted) scope.
#
# Environment:
#   FRAMAC_WP_CACHE     WP cache mode (default: replay). See CACHE section.
#   FRAMAC_WP_CACHEDIR  Override the cache directory (default: ./wp-cache).
#   FRAMAC_WP_PAR       Concurrent prover processes (default: 8; 1 = deterministic).
# ----------------------------------------------------------------------------
set -eu

# Resolve paths relative to THIS script, not the caller's cwd, so the in-tree
# source/headers are found no matter where run_wp.sh is invoked from (including
# inside the Docker container, where the repo is bind-mounted).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)   # proof/punycode -> repo root

# A bare 'prove'/'report'/'check-scope' is the MODE. Anything else is an error.
MODE=""
for arg in "$@"; do
    case "$arg" in
        prove|report|check-scope) MODE="$arg" ;;
        *) echo "$0: unknown argument: $arg" >&2
           echo "usage: $0 [prove|report|check-scope]" >&2
           exit 2 ;;
    esac
done
MODE="${MODE:-prove}"

# Race Alt-Ergo + Z3 + cvc5 per goal (union of their strengths -- see header).
PROVERS="alt-ergo,z3,cvc5"

# Generous per-goal timeout so a slow runner never yields a false timeout red.
# Env-overridable (FRAMAC_WP_TIMEOUT): raise it when regenerating the cache on a
# slow/emulated toolchain -- e.g. the amd64 pinned image under QEMU on an arm64
# host runs the solvers ~10x slower, so goals that prove in well under 30s on
# native CI need a larger budget just to be cached. Only bites on a cache MISS;
# committed-cache replay never calls a solver.
TIMEOUT="${FRAMAC_WP_TIMEOUT:-30}"

# Canonical proof scope -- ONE source of truth, shared by the -wp-fct flag and
# the check-scope guard. ENTRY is the reachability root; SCOPE_FCTS is ENTRY plus
# every in-tree function reachable from it that we prove.
SCOPE_ENTRY="ossl_a2ulabel"
SCOPE_FCTS="ossl_a2ulabel codepoint2utf8 ossl_punycode_decode adapt is_basic digit_decoded ossl_assert_int"

# MUST-COVER FLOOR for check-scope: the functions this proof COMMITS to keeping
# in verified scope no matter how the call tree is refactored. These are the two
# attacker-facing entrypoints (ossl_a2ulabel parses the label; ossl_punycode_decode
# is the original CVE-2022-3786 locus). check-scope fails LOUDLY if either ever
# falls out of the scope reachable from SCOPE_ENTRY -- see that mode's comment for
# why a bare STALE/MISSING diff is not enough here.
MUST_COVER="ossl_punycode_decode ossl_a2ulabel"

# The source under proof and the flags the real translation unit needs.
SRC="$REPO_ROOT/crypto/punycode.c"
TARGET_CPP="-cpp-extra-args=-I$REPO_ROOT/include -include $SCRIPT_DIR/wpacket_spec.h"
TARGET_FCT="$(printf '%s' "$SCOPE_FCTS" | tr ' ' ',')"

# CACHE: serve recorded proofs from a cache dir so a run skips the solvers on a
# hit. Mode/dir/parallelism come from the env vars below (defaults here);
# run_proofs.pl sets them per its three workflows -- see that script for policy:
#   update  = use cache, run solvers on a MISS, and WRITE new entries. Fast local
#             proving writes into a SCRATCH (gitignored) dir, so stale entries
#             accumulate harmlessly and the committed cache is never touched.
#   rebuild = always run solvers and write -- used by 'run_proofs.pl --save' (with
#             FRAMAC_WP_PAR=1) to regenerate the COMMITTED wp-cache/ deterministically.
#   replay  = use cache; on a MISS run solvers but do NOT write. run_proofs.pl
#             --load uses it as TIER 2 -- only after the offline tier below missed --
#             to re-derive the changed goals live, and so distinguish a merely STALE
#             cache (still proves => advisory) from a real REGRESSION (fails). Also
#             this script's ad-hoc standalone default.
#   offline = use cache but NEVER run a solver; a miss leaves the goal unproved, so
#             the "Proved goals: N / M" gate reports N < M. run_proofs.pl --load
#             uses it as TIER 1 (fast, deterministic, no solver): all goals proved
#             means the cache is fresh AND the proof holds -- the common case. The
#             "[Cache]" line is NOT parsed; N == M is the whole freshness signal.
#             --save also uses offline to confirm a freshly written cache stands
#             alone (covers every goal with no solver).
CACHE_MODE="${FRAMAC_WP_CACHE:-replay}"
CACHE_DIR="${FRAMAC_WP_CACHEDIR:-$SCRIPT_DIR/wp-cache}"
PAR="${FRAMAC_WP_PAR:-8}"

# Build the WP argv (prove/report) from the setup above. Kept in "$@" so a path
# with separators stays one properly-quoted argument.
set --
set -- "$@" "$TARGET_CPP"
set -- "$@" -wp-model Typed+cast
set -- "$@" -instantiate -wp -wp-rte -wp-prover "$PROVERS" -wp-timeout "$TIMEOUT"
set -- "$@" -wp-par "$PAR"
set -- "$@" -wp-cache "$CACHE_MODE" -wp-cache-dir "$CACHE_DIR"
set -- "$@" -wp-fct "$TARGET_FCT"

case "$MODE" in
    prove)
        # Frama-C exits 0 even when WP goals are left unproved, so its exit code
        # alone does NOT gate the proof. Capture the run, echo it, then enforce
        # completeness from the "Proved goals: N / M" summary: N < M (or a missing
        # summary, e.g. an offline cache miss) is a hard failure. This is a single
        # cache-mode PRIMITIVE; the freshness-vs-regression distinction (running an
        # offline pass then, on a miss, a replay pass) is orchestrated by
        # run_proofs.pl, so nothing here parses the version-specific "[Cache]" line.
        set +e
        out=$(frama-c "$@" "$SRC" 2>&1); rc=$?
        set -e
        printf '%s\n' "$out"
        [ "$rc" -eq 0 ] || exit "$rc"     # parse/user error etc. -- propagate
        line=$(printf '%s\n' "$out" | grep -E 'Proved goals:' | tail -1)
        n=$(printf '%s' "$line" | sed -n 's/.*Proved goals: *\([0-9][0-9]*\) *\/ *\([0-9][0-9]*\).*/\1/p')
        m=$(printf '%s' "$line" | sed -n 's/.*Proved goals: *\([0-9][0-9]*\) *\/ *\([0-9][0-9]*\).*/\2/p')
        if [ -z "$m" ] || [ "$n" != "$m" ]; then
            echo "run_wp.sh: WP did not prove all goals (${line:-no 'Proved goals' summary})" >&2
            exit 1
        fi
        ;;
    report)
        CSV="$(mktemp)"
        trap 'rm -f "$CSV"' EXIT
        TAB="$(printf '\t')"
        frama-c "$@" "$SRC" -then -report-csv "$CSV" >/dev/null 2>&1
        # CSV columns: directory<tab>file<tab>line<tab>function<tab>kind<tab>status<tab>property
        # Keep unproven properties (status != Valid), reduce file to basename, emit a
        # tab-keyed record, sort by file then numeric line, then pretty-print.
        awk -F"$TAB" 'NR>1 && $6!="Valid" && $3!="" {
                 n = split($2, p, "/"); f = p[n];
                 printf "%s\t%s\t[%s] %s: %s\n", f, $3, $6, $5, $7
             }' "$CSV" \
          | sort -t"$TAB" -k1,1 -k2,2n \
          | awk -F"$TAB" '{ printf "%-12s:%-5s %s\n", $1, $2, $3 }'
        ;;
    check-scope)
        # DRIFT GUARD for the -wp-fct scope. WP is modular -- a function reachable
        # from SCOPE_ENTRY but OUTSIDE the proven scope has its ACSL contract
        # ASSUMED, never checked (a silent soundness gap if a new helper is added
        # with a wrong contract). Recompute the scope from the source and fail if
        # it differs from SCOPE_FCTS in EITHER direction:
        #
        #   computed = { reachable from SCOPE_ENTRY }  (-cg callgraph, BFS)
        #            INTERSECT { defined in this TU }   (-metrics)
        #
        # The intersection drops libc leaves (memmove, ...): reachable but undefined
        # here, so trusted via their library contract by design, not proved.
        DOT="$(mktemp)"; MET="$(mktemp)"
        trap 'rm -f "$DOT" "$MET"' EXIT
        # Raw callgraph + metrics ONLY. NO -instantiate (it would rewrite memmove ->
        # memmove_uint and distort the graph); NO -wp (not needed here).
        frama-c "$TARGET_CPP" "$SRC" -cg "$DOT" -metrics >"$MET" 2>/dev/null

        # DEFINED: names from the -metrics "Defined functions" block ("name (N call)").
        DEFINED="$(sed -n '/Defined functions/,/Specified-only/p' "$MET" \
            | grep -oE '[A-Za-z_][A-Za-z0-9_]* \([0-9]+ call\)' | sed 's/ (.*//')"
        # REACH: BFS from SCOPE_ENTRY over callgraph edges
        #        ("UV src (id)" -> "UV dst (id)").
        REACH="$(sed -n 's/.*"UV \([A-Za-z0-9_]*\) ([0-9]*)" -> "UV \([A-Za-z0-9_]*\) ([0-9]*)".*/\1 \2/p' "$DOT" \
            | awk -v root="$SCOPE_ENTRY" '
                { adj[$1] = adj[$1] " " $2 }
                END {
                    q[0] = root; n = 1; seen[root] = 1
                    for (h = 0; h < n; h++) {
                        m = split(adj[q[h]], o, " ")
                        for (j = 1; j <= m; j++)
                            if (o[j] != "" && !(o[j] in seen)) { seen[o[j]] = 1; q[n++] = o[j] }
                    }
                    for (k in seen) print k
                }')"

        # MUST-COVER FLOOR (runs BEFORE the STALE/MISSING diff, and short-circuits).
        # The diff below keeps SCOPE_FCTS equal to the computed scope, but for a
        # committed entrypoint that is the WRONG remedy: if a refactor makes
        # ossl_punycode_decode unreachable from ossl_a2ulabel, the diff would emit
        # "STALE: drop ossl_punycode_decode from SCOPE_FCTS" -- silently retiring
        # the guarantee we promised. So first assert MUST_COVER is a subset of the
        # computed (REACH ∩ DEFINED) scope, independent of SCOPE_FCTS (no list edit
        # can paper over a genuine dropout). If this floor is breached, report only
        # it and stop: a missing must-cover root makes any concurrent STALE/MISSING
        # noise moot (you cannot sensibly fix both at once), and the remedy is the
        # opposite of STALE's -- restore reachability or give the function its own
        # proof root; never trim it away.
        UNCOVERED="$( { printf 'R %s\n' $REACH; printf 'D %s\n' $DEFINED; printf 'M %s\n' $MUST_COVER; } \
            | awk '
                $1=="R"{r[$2]=1} $1=="D"{d[$2]=1} $1=="M"{m[$2]=1}
                END { for (f in m) if (!(f in r) || !(f in d)) print f }' | sort)"
        if [ -n "$UNCOVERED" ]; then
            echo "check-scope FAILED: a MUST-COVER entrypoint fell out of the proof scope." >&2
            echo "" >&2
            printf '%s\n' "$UNCOVERED" | while read -r fn; do
                echo "  [!] $fn  is a committed entrypoint but is NO LONGER reachable from" >&2
                echo "      $SCOPE_ENTRY and defined in-tree, so it is no longer proved." >&2
                echo "      This proof PROMISES to keep '$fn' verified. Do NOT drop it from" >&2
                echo "      SCOPE_FCTS. Fix: restore the call path from $SCOPE_ENTRY, or give" >&2
                echo "      '$fn' its own proof root (a separate proof/<name>/run_wp.sh)." >&2
                echo "" >&2
            done
            echo "  MUST_COVER = { $MUST_COVER }" >&2
            exit 1
        fi

        # Diff computed (REACH ∩ DEFINED) against declared SCOPE_FCTS: one awk over
        # three labelled streams, one output line per discrepancy.
        DIFF="$( { printf 'R %s\n' $REACH; printf 'D %s\n' $DEFINED; printf 'E %s\n' $SCOPE_FCTS; } \
            | awk '
                $1=="R"{r[$2]=1} $1=="D"{d[$2]=1} $1=="E"{e[$2]=1}
                END {
                    for (f in r) if (f in d) c[f]=1         # computed = R intersect D
                    for (f in c) if (!(f in e)) print "MISSING " f
                    for (f in e) if (!(f in c)) print "STALE " f
                }' | sort)"

        if [ -z "$DIFF" ]; then
            echo "check-scope OK: verified scope matches the in-tree functions"
            echo "  reachable from $SCOPE_ENTRY."
            echo "  SCOPE_FCTS = { $SCOPE_FCTS }"
            exit 0
        fi

        echo "check-scope FAILED: the -wp-fct scope is out of date." >&2
        echo "" >&2
        printf '%s\n' "$DIFF" | while read -r kind fn; do
            case "$kind" in
                MISSING)
                    echo "  [+] $fn  is reachable from $SCOPE_ENTRY and DEFINED in-tree, but is" >&2
                    echo "      NOT in the verified scope. WP would ASSUME its contract without" >&2
                    echo "      checking it -- a potential soundness gap. Fix: add '$fn' to" >&2
                    echo "      SCOPE_FCTS in this script AND annotate it so WP can discharge it." >&2
                    ;;
                STALE)
                    echo "  [-] $fn  is in the verified scope but is NO LONGER reachable from" >&2
                    echo "      $SCOPE_ENTRY (renamed, removed, or its call site was deleted)." >&2
                    echo "      Fix: drop '$fn' from SCOPE_FCTS, or restore the call." >&2
                    ;;
            esac
            echo "" >&2
        done
        exit 1
        ;;
esac
