#! /bin/sh
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# run_wp.sh -- Frama-C WP runner for ossl_punycode_decode in crypto/punycode.c.
#
# Deductive verification (Frama-C WP) of ossl_punycode_decode() and its helpers
# (adapt, is_basic, digit_decoded), proved against the ACSL contracts written
# into crypto/punycode.c. Unlike a dynamic or bounded check, WP proves the
# obligations ONCE, symbolically, for all inputs and buffer sizes; it needs no
# driver harness because it is modular deductive verification.
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
#   -cpp-extra-args=-I<repo>/include
#               Frama-C preprocesses with -nostdinc and its own libc, so
#               OpenSSL's headers (e_os2.h, crypto/punycode.h, internal/common.h,
#               ...) are unfindable without the project include dir. With it the
#               whole translation unit parses; the only residue is benign
#               safestack.h cast warnings, outside our functions.
#
#   -wp-fct ossl_punycode_decode,adapt,is_basic,digit_decoded
#               Scope the obligation set to the proof's functions. WP is modular,
#               so without this it would ALSO emit goals for the unannotated
#               ossl_a2ulabel / codepoint2utf8 in the same file (their out[]
#               writes, strchr/strlen preconditions, WPACKET machinery) -- noise
#               we make no claims about. Scoping is exactly what separates "our
#               proof" from "the rest of the file". SCOPE_FCTS below is the single
#               source of truth for this list, shared with the check-scope guard.
#
#   -wp-timeout 30
#               Generous per-goal timeout (~15x the time any goal needs on a
#               developer box) so a slow CI runner never produces a false red
#               "timeout" failure. With the committed proof cache (replay mode,
#               below) goals are normally replayed without calling a solver at
#               all, so this only matters on a cache miss.
#
#   -wp-cache replay / -wp-cache-dir wp-cache/ (see CACHE section below)
#               Replay recorded proofs from the committed wp-cache/ directory
#               instead of rediscovering them each run -- the single biggest
#               robustness win against timeout flakiness in CI.
#
# RESULT: 104 / 104 goals proved in scope. The only residue is the memmove_uint
# trust-base stub described above. Scope honesty: this covers
# ossl_punycode_decode ONLY, not ossl_a2ulabel (the WPACKET-based caller that
# actually held CVE-2022-3786); decode is the tractable island.
#
# For a source-located view of all obligations, run:  ./run_wp.sh report
# ----------------------------------------------------------------------------
#
# Usage:
#   ./run_wp.sh [prove|report|check-scope]
#
#   prove       -- (default) run WP+RTE, the proof itself. Lists per-VC goal
#                  results with WP-internal names.
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
TIMEOUT=30

# Canonical proof scope -- ONE source of truth, shared by the -wp-fct flag and
# the check-scope guard. ENTRY is the reachability root; SCOPE_FCTS is ENTRY plus
# every in-tree function reachable from it that we prove.
SCOPE_ENTRY="ossl_punycode_decode"
SCOPE_FCTS="ossl_punycode_decode adapt is_basic digit_decoded"

# The source under proof and the flags the real translation unit needs.
SRC="$REPO_ROOT/crypto/punycode.c"
TARGET_CPP="-cpp-extra-args=-I$REPO_ROOT/include"
TARGET_FCT="$(printf '%s' "$SCOPE_FCTS" | tr ' ' ',')"

# CACHE: replay recorded proofs from the committed wp-cache/ so CI (and repeat
# local runs) skip the solvers entirely on a hit. The two env vars below override
# these defaults without editing the script (read here and passed as flags):
#   replay  = use the cache; on a MISS run the solvers but do NOT update the
#             cache (so a stale/broken cache surfaces as real solver work, and CI
#             never silently rewrites the committed cache).
#   update  = use the cache, and WRITE new/changed entries -- used once, locally,
#             to (re)populate wp-cache/ after an intended proof change.
CACHE_MODE="${FRAMAC_WP_CACHE:-replay}"
CACHE_DIR="${FRAMAC_WP_CACHEDIR:-$SCRIPT_DIR/wp-cache}"

# Build the WP argv (prove/report) from the setup above. Kept in "$@" so a path
# with separators stays one properly-quoted argument.
set --
set -- "$@" "$TARGET_CPP"
set -- "$@" -instantiate -wp -wp-rte -wp-prover "$PROVERS" -wp-timeout "$TIMEOUT"
set -- "$@" -wp-cache "$CACHE_MODE" -wp-cache-dir "$CACHE_DIR"
set -- "$@" -wp-fct "$TARGET_FCT"

case "$MODE" in
    prove)
        frama-c "$@" "$SRC"
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
