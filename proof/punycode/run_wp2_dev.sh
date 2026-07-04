#! /bin/sh
# Dev-only WP runner for ENTRY 2 (ossl_a2ulabel). Throwaway; the durable
# version folds into proof/punycode/run_wp.sh at the end of the branch.
#
# Uses an "update" cache so dev iterations are fast and never
# touch the committed proof/punycode/wp-cache. Flags carried from the spikes:
#   -wp-literals       string-literal contents modeled concretely (entry2 spike)
#   -wp-model Typed+cast   char* <-> unsigned char* casts (loop 4)
#   -include wpacket_spec.h   trust-base WPACKET contracts (loop 4)
set -eu

REPO="$HOME/Projects/openssl"
SPEC="$REPO/proof/punycode/wpacket_spec.h"
CACHE="$REPO/proof/punycode/wp2-cache-dev"
FCT="${WP2_FCT:-ossl_a2ulabel}"
MODE="${1:-prove}"

mkdir -p "$CACHE"

set --
set -- "$@" -cpp-extra-args="-I$REPO/include -include $SPEC"
set -- "$@" -wp-literals
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
        n=split($2,p,"/"); printf "%-5s [%s] %s: %s\n", $3, $6, $5, $7 }' "$CSV" \
      | sort -k1,1n
    rm -f "$CSV"
    ;;
esac
