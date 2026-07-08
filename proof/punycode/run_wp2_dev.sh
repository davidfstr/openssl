#! /bin/sh
# Dev-only WP runner for ENTRY 2 (ossl_a2ulabel). Throwaway; the durable
# version folds into proof/punycode/run_wp.sh at the end of the branch.
#
# Uses an "update" cache so dev iterations are fast and never
# touch the committed proof/punycode/wp-cache. Flags carried from the spikes:
#   -wp-model Typed+cast   char* <-> unsigned char* casts (loop 4)
#   -include wpacket_spec.h   trust-base WPACKET contracts (loop 4)
# (-wp-literals was dropped once the "xn--" prefix test was unrolled by hand:
#  no string literal remains in scope, so concrete literal modeling is moot.)
set -eu

REPO="$HOME/Projects/openssl"
SPEC="$REPO/proof/punycode/wpacket_spec.h"
CACHE="$REPO/proof/punycode/wp2-cache-dev"
# Scope: ossl_a2ulabel plus codepoint2utf8, the one in-tree callee that is
# reachable+defined but NOT covered by entry 1's decode-rooted proof. Without it
# here, WP would ASSUME its contract (a silent, unchecked gap); in scope, its
# contract is discharged (44 goals). The decode subtree (ossl_punycode_decode,
# adapt, is_basic, digit_decoded) is deliberately NOT listed: its contracts are
# assumed here and proved by entry 1's run_wp.sh. That split is what Task 3's
# A-vs-B gate revisits before this folds into the production runner.
FCT="${WP2_FCT:-ossl_a2ulabel,codepoint2utf8}"
MODE="${1:-prove}"

mkdir -p "$CACHE"

set --
set -- "$@" -cpp-extra-args="-I$REPO/include -include $SPEC"
set -- "$@" -instantiate -wp -wp-rte -wp-model Typed+cast
set -- "$@" -wp-prover alt-ergo,z3,cvc5 -wp-timeout 10 -wp-par 8
set -- "$@" -wp-cache update -wp-cache-dir "$CACHE"
set -- "$@" -wp-fct "$FCT"

case "$MODE" in
  prove)
    frama-c "$@" "$REPO/crypto/punycode.c"
    ;;
  report)
    CSV="$(mktemp)"; TAB="$(printf '\t')"
    frama-c "$@" "$REPO/crypto/punycode.c" -then -report-csv "$CSV" >/dev/null 2>&1
    awk -F"$TAB" 'NR>1 && $6!="Valid" && $3!="" {
             n = split($2, p, "/"); f = p[n];
             printf "%s\t%s\t[%s] %s: %s\n", f, $3, $6, $5, $7
          }' "$CSV" \
      | sort -t"$TAB" -k1,1 -k2,2n \
      | awk -F"$TAB" '{ printf "%-12s:%-5s %s\n", $1, $2, $3 }'
    rm -f "$CSV"
    ;;
esac
