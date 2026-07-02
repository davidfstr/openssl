#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# run_proofs.pl -- single entrypoint for the formal proofs under proof/.
#
# Runs every proof (today: punycode) inside a pinned Docker toolchain
# (proof/docker/Dockerfile) so results are reproducible and cannot drift with
# the host's Frama-C / solver versions. For each proof it runs the drift guard
# (check-scope) and then the proof itself (prove). Exit status is 0 iff every
# step of every proof passes.
#
# Usage:
#   ./proof/run_proofs.pl                 run all proofs in the pinned container
#   ./proof/run_proofs.pl --no-docker     use a local Frama-C install instead
#   ./proof/run_proofs.pl --update-cache  (re)populate each proof's committed WP
#                                         cache; use after an intended proof
#                                         change, then commit the updated cache.
#
# On success the trust base and scope of what was proved are printed: a green
# result is only meaningful together with the assumptions it rests on.

use strict;
use warnings;
use File::Basename qw(basename dirname);
use Cwd qw(abs_path);

my $PROOF_DIR = dirname(abs_path($0));       # .../proof
my $REPO_ROOT = dirname($PROOF_DIR);         # repo root
my $IMAGE     = "openssl-proof-tools";       # locally-built pinned toolchain
my $CONTACT   = "David Foster (\@davidfstr, david AT dafoster DOT net)";

# --- options ---------------------------------------------------------------
my $use_docker   = 1;
my $update_cache = 0;
for my $arg (@ARGV) {
    if    ($arg eq "--no-docker")    { $use_docker = 0; }
    elsif ($arg eq "--update-cache") { $update_cache = 1; }
    elsif ($arg eq "-h" || $arg eq "--help") { usage(); exit 0; }
    else { print STDERR "$0: unknown argument: $arg\n"; usage(); exit 2; }
}

sub usage {
    print STDERR <<"EOF";
usage: $0 [--no-docker] [--update-cache]
  --no-docker     run proofs against a local Frama-C install (no container)
  --update-cache  (re)populate each proof's committed WP cache, then exit
EOF
}

# --- discover proofs: each proof is a proof/<name>/run_wp.sh runner ---------
my @runners = sort glob("$PROOF_DIR/*/run_wp.sh");
die "$0: no proofs found under $PROOF_DIR/*/run_wp.sh\n" unless @runners;

# --- build the pinned toolchain image (fast once layers are cached) ---------
if ($use_docker) {
    print "=== building pinned proof toolchain ($IMAGE) ===\n";
    my $rc = run_cmd("docker", "build", "-t", $IMAGE, "$PROOF_DIR/docker");
    if ($rc != 0) {
        print STDERR <<"EOF";

FAILED to build the proof toolchain image. Docker must be installed and
running. To run without Docker against a local Frama-C 31 + Alt-Ergo/Z3/cvc5
install, use:  $0 --no-docker
EOF
        exit 1;
    }
}

# --- run each proof ---------------------------------------------------------
my @failures;
for my $runner (@runners) {
    my $name = basename(dirname($runner));           # e.g. "punycode"
    if ($update_cache) {
        push @failures, "$name/update-cache" unless update_cache_for($name);
    } else {
        # check-scope (drift guard) then prove (replays the committed cache).
        for my $mode ("check-scope", "prove") {
            print "\n=== proof: $name  ($mode, cache=replay) ===\n";
            push @failures, "$name/$mode" if run_proof($name, $mode, "replay") != 0;
        }
    }
}

# --- report -----------------------------------------------------------------
if (@failures) {
    print_failure(\@failures);
    exit 1;
}
if ($update_cache) {
    print "\nCache (re)populated. Review and commit the updated proof/*/wp-cache/.\n";
    exit 0;
}
print_success(\@runners);
exit 0;

# ---------------------------------------------------------------------------

# Build the argv to run one proof/mode, either in the container or natively. The
# per-proof runner resolves the repo root from its own location, so cwd does not
# matter natively; in the container the repo is bind-mounted at /src and
# run_wp.sh lives at the same relative path. Cache mode is passed via the
# FRAMAC_WP_CACHE env var (docker -e, or the child's environment natively).
sub proof_cmd {
    my ($name, $mode, $cache) = @_;
    my $rel = "proof/$name/run_wp.sh";
    if ($use_docker) {
        return ("docker", "run", "--rm",
                "-v", "$REPO_ROOT:/src", "-w", "/src",
                "-e", "FRAMAC_WP_CACHE=$cache",
                $IMAGE, $rel, $mode);
    } else {
        $ENV{FRAMAC_WP_CACHE} = $cache;   # inherited by the child
        return ("$REPO_ROOT/$rel", $mode);
    }
}

sub run_proof {
    my ($name, $mode, $cache) = @_;
    return run_cmd(proof_cmd($name, $mode, $cache));
}

# (Re)populate one proof's committed WP cache, converging over repeated passes.
# The prover portfolio races Alt-Ergo/Z3/cvc5, so which solver first closes a
# contested goal -- and thus that goal's cache key -- can vary run to run. One
# 'update' pass therefore may leave a few goals uncached; we re-run until a pass
# writes nothing new (or a safety cap), so the committed cache replays as a full
# hit in CI. Returns true on success.
sub update_cache_for {
    my ($name) = @_;
    my $MAX_PASSES = 6;
    for my $pass (1 .. $MAX_PASSES) {
        print "\n=== proof: $name  (prove, cache=update, pass $pass) ===\n";
        my ($rc, $out) = run_capture(proof_cmd($name, "prove", "update"));
        return 0 if $rc != 0;
        # WP prints "[Cache] found:N" when nothing new was written, or
        # "[Cache] ... updated:M" when it added M entries. Stable once no updates.
        if ($out !~ /\bupdated:(\d+)/ || $1 == 0) {
            print "cache stable for $name after pass $pass\n";
            return 1;
        }
    }
    print STDERR "cache for $name did not stabilise within $MAX_PASSES passes\n";
    return 0;
}

# system() wrapper returning the child's exit code (or non-zero on spawn/signal).
sub run_cmd {
    my @cmd = @_;
    print "+ @cmd\n";
    my $status = system(@cmd);
    return exit_code($status, $cmd[0]);
}

# Like run_cmd, but also captures combined stdout+stderr (still echoed live).
# Returns (exit_code, captured_text).
sub run_capture {
    my @cmd = @_;
    print "+ @cmd\n";
    my $out = "";
    my $pid = open(my $fh, "-|");
    die "fork failed: $!\n" unless defined $pid;
    if ($pid == 0) {                 # child
        open(STDERR, ">&", \*STDOUT) or die;
        exec { $cmd[0] } @cmd or die "exec failed: $cmd[0]: $!\n";
    }
    while (my $line = <$fh>) { print $line; $out .= $line; }
    close($fh);
    return (exit_code($?, $cmd[0]), $out);
}

sub exit_code {
    my ($status, $prog) = @_;
    if ($status == -1)    { print STDERR "failed to run: $prog: $!\n"; return 127; }
    elsif ($status & 127) { return 128 + ($status & 127); }   # died on signal
    else                  { return $status >> 8; }
}

sub print_success {
    my ($runners) = @_;
    my @names = map { basename(dirname($_)) } @$runners;
    print <<"EOF";

============================================================================
ALL PROOFS PASSED (@{[ scalar @$runners ]}): @names

What this means -- and, just as importantly, what it does NOT mean:

Frama-C's WP plugin discharged every verification obligation, symbolically and
for all inputs, for the functions in scope. This is NOT a test run; there are no
input sizes it did not cover. But the result holds only MODULO an explicit trust
base and set of caller obligations:

  punycode (ossl_punycode_decode in crypto/punycode.c):
    * TRUST BASE: one assumption, confined to a single generated stub --
      a libc memmove of 4k bytes behaves as an element-wise move of k uint32s
      (WP's typed memory model cannot relate byte-wise memmove to the uint32
      buffer; -instantiate relocates the gap into memmove_uint's assigns clause).
    * CALLER OBLIGATIONS (the requires clauses, discharged onto callers):
        - the pEncoded / pDecoded / pout_length buffers are valid as described;
        - enc_len <= UINT_MAX  (needed for termination; upstream also guards this
          at runtime);
        - *pout_length < UINT_MAX  (excludes a latent divide-by-zero in adapt;
          unreachable from any sane caller, but real for the function in
          isolation, and NOT guarded upstream).
    * SCOPE: this proves ossl_punycode_decode ONLY. It does NOT verify
      ossl_a2ulabel (the WPACKET-based caller that actually held CVE-2022-3786).
      The check-scope guard confirms no reachable in-tree callee slipped outside
      the proved set (where WP would merely ASSUME its contract).

See proof/README.md for the full statement.
============================================================================
EOF
}

sub print_failure {
    my ($failures) = @_;
    print STDERR <<"EOF";

============================================================================
PROOF FAILURE in: @$failures

A verification obligation could not be discharged, or the proved-function scope
drifted. Likely causes, most common first:

  1. The proved code (e.g. crypto/punycode.c) changed and an ACSL annotation no
     longer matches it. Re-run the failing proof in 'report' mode for a
     source-located list of every unproven obligation, e.g.:
         ./proof/punycode/run_wp.sh report
  2. A new function reachable from the proof entry point was added but not added
     to SCOPE_FCTS (a 'check-scope' MISSING failure) -- WP would otherwise ASSUME
     its contract without checking it. The failure message names the function.
  3. A genuine prover timeout on a cache miss (rare, given the generous timeout).
     If the proof itself is unchanged, re-populating the cache may help:
         ./proof/run_proofs.pl --update-cache

If you changed crypto/punycode.c and cannot work out how to repair the proof,
the point of contact is $CONTACT -- reach out and I will help.
============================================================================
EOF
}
