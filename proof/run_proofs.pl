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
# (proof/docker/Dockerfile.multiarch, built from source so it runs natively on
# the host arch) so results are reproducible and cannot drift with the host's
# Frama-C / solver versions. For each proof it runs the drift guard
# (check-scope) and then the proof itself (prove). Exit status is 0 iff every
# step of every proof passes.
#
# Three workflows, differing only in how they use the WP proof cache:
#
#   (default)   PROVE LOCALLY -- fast, for a human iterating on the proof. Races
#               the solver portfolio and caches results in a gitignored SCRATCH
#               dir (never the committed cache), so repeat runs are quick and
#               stale entries accumulate harmlessly. Determinism does not matter
#               here, so this is the plain, no-argument default.
#
#   --load      VERIFY AGAINST COMMITTED ARTIFACTS (the CI path), two-tier so a
#               green check answers the contributor's question ("does my change
#               still prove?") apart from the maintenance one ("is the cache
#               fresh?"). Tier 1 replays the committed cache OFFLINE (no solver): if
#               it discharges every goal the cache is fresh AND the proof holds --
#               fast, deterministic, the common case. Only on a miss does tier 2
#               REPLAY re-derive the missed goals with the solvers: proving them
#               means the cache was merely stale (PASS + advisory to run --save);
#               failing to prove them is a real regression (FAIL). It never fails
#               merely because the cache drifted. Both tiers gate on "Proved goals:
#               N / M" -- the version-specific "[Cache]" line is never parsed.
#
#   --save      REGENERATE COMMITTED ARTIFACTS -- wipe and rebuild each proof's
#               committed wp-cache/ from scratch, running solvers in a fixed,
#               single-threaded order so the winning prover per goal (hence the
#               cache) is identical on every machine, then verify the written cache
#               stands alone (offline replay must hit every goal). Must run in the
#               pinned container so the cached prover versions match CI. Commit the
#               result.
#
# Also: --no-docker runs against a local Frama-C install instead of the container
# (not allowed with --save, whose cache must match the pinned provers).
#
# On success the trust base and scope of what was proved are printed: a green
# result is only meaningful together with the assumptions it rests on.

use strict;
use warnings;
use File::Basename qw(basename dirname);
use Cwd qw(abs_path getcwd);

my $PROOF_DIR = dirname(abs_path($0));       # .../proof
my $REPO_ROOT = dirname($PROOF_DIR);         # repo root
my $IMAGE     = "openssl-proof-tools";       # locally-built pinned toolchain
# The toolchain image is built FROM SOURCE via Dockerfile.multiarch so it runs
# NATIVELY on the build host's arch (arm64 locally, amd64 in CI) rather than
# under QEMU. This is what makes a --save cache regeneration fast off the x86
# CI path -- and, because the lockfile pins why3/Alt-Ergo identically on both
# arches, lets a cache regenerated on one arch replay on the other. (The older
# amd64-only, Z3/cvc5-bearing proof/docker/Dockerfile is kept for the deferred
# convergence decision but is no longer the one we build.)
my $DOCKERFILE = "Dockerfile.multiarch";
my $CONTACT   = "David Foster (\@davidfstr, david AT dafoster DOT net)";

# --- options ---------------------------------------------------------------
my $use_docker  = 1;
my $build_image = 1;
my $workflow    = "prove";       # prove (default) | load | save
for my $arg (@ARGV) {
    if    ($arg eq "--no-docker") { $use_docker = 0; }
    elsif ($arg eq "--no-build")  { $build_image = 0; }
    elsif ($arg eq "--load")      { $workflow = "load"; }
    elsif ($arg eq "--save")      { $workflow = "save"; }
    elsif ($arg eq "-h" || $arg eq "--help") { usage(); exit 0; }
    else { print STDERR "$0: unknown argument: $arg\n"; usage(); exit 2; }
}
if ($workflow eq "save" && !$use_docker) {
    print STDERR "$0: --save must run in the pinned container (its cache is "
               . "prover-version specific); drop --no-docker.\n";
    exit 2;
}

sub usage {
    print STDERR <<"EOF";
usage: $0 [--load | --save] [--no-docker] [--no-build]
  (default)     prove locally: race solvers, cache to a scratch dir (fast)
  --load        replay the committed cache (CI): re-prove on a miss; a stale
                cache still passes with an advisory, only a real regression fails
  --save        wipe + regenerate each proof's committed cache deterministically,
                then verify it stands alone offline
  --no-docker   use a local Frama-C install instead of the container
  --no-build    reuse an already-present '$IMAGE' image instead of building it
                (CI builds + caches the image via buildx before calling this)
EOF
}

# WP cache profile for the SINGLE-PASS workflows (prove, save); --load is
# two-tier and sets its own modes inline in the loop below. 'scratch' is a
# gitignored per-proof dir; 'committed' is the checked-in wp-cache/. par=1 makes
# the winning prover per goal deterministic (see run_wp.sh) and is needed only by
# --save, whose output cache must be reproducible.
my %PROFILE = (
    prove => { cache => "update",  dir => "scratch",   par => 8 },
    save  => { cache => "rebuild", dir => "committed", par => 1 },
);

# --- discover proofs: each proof is a proof/<name>/run_wp.sh runner ---------
my @runners = sort glob("$PROOF_DIR/*/run_wp.sh");
die "$0: no proofs found under $PROOF_DIR/*/run_wp.sh\n" unless @runners;

# --- make sure the generated headers the proof parses are present -----------
ensure_generated_headers();

# --- obtain the pinned toolchain image --------------------------------------
# Default: build it here (fast once layers are cached locally). Under --no-build
# the image is expected to already exist -- CI builds and layer-caches it with
# buildx (docker/build-push-action, cache-from/to type=gha) before calling us, so
# the slow base-image pull + solver install happens once per cache lifetime, not
# every run.
if ($use_docker && $build_image) {
    print "=== building pinned proof toolchain ($IMAGE, $DOCKERFILE) ===\n";
    my $rc = run_cmd("docker", "build", "-t", $IMAGE,
                     "-f", "$PROOF_DIR/docker/$DOCKERFILE", "$PROOF_DIR/docker");
    if ($rc != 0) {
        print STDERR <<"EOF";

FAILED to build the proof toolchain image. Docker must be installed and
running. To run without Docker against a local Frama-C 31 + Alt-Ergo/Z3/cvc5
install, use:  $0 --no-docker
EOF
        exit 1;
    }
} elsif ($use_docker) {   # --no-build: image must already be present
    print "=== using pre-built proof toolchain ($IMAGE) ===\n";
    if (system("docker image inspect $IMAGE >/dev/null 2>&1") != 0) {
        print STDERR <<"EOF";

--no-build was given but the image '$IMAGE' is not present. In CI the workflow
builds and caches this image (docker/build-push-action) before invoking
run_proofs.pl. Locally, drop --no-build so run_proofs.pl builds it itself.
EOF
        exit 1;
    }
}

# --- run each proof ---------------------------------------------------------
my $prof = $PROFILE{$workflow};
my @failures;
my @stale;
for my $runner (@runners) {
    my $name = basename(dirname($runner));           # e.g. "punycode"

    # check-scope is the -wp-fct drift guard; it uses no cache, so run it first
    # (and, for --save, refuse to regenerate a cache for a drifted scope).
    print "\n=== proof: $name  (check-scope) ===\n";
    if (run_cmd(proof_cmd($name, "check-scope", undef)) != 0) {
        push @failures, "$name/check-scope";
        next;
    }

    # --save rebuilds from scratch, so wipe the committed cache first (no orphan
    # entries from since-deleted goals linger in the committed artifact).
    wipe_committed_cache($name) if $workflow eq "save";

    if ($workflow eq "load") {
        # TWO-TIER, so a green check answers the contributor's question ("does my
        # change still prove?") separately from the maintenance one ("is the cache
        # fresh?"). Both tiers gate purely on "Proved goals: N / M"; neither parses
        # the version-specific "[Cache]" line.
        #
        # Tier 1 -- OFFLINE: replay the committed cache with NO solver. If it proves
        # every goal, the cache is fresh AND the proof holds: fast, deterministic,
        # the common case. A miss leaves goals unproved (N < M), which is the ONLY
        # thing that drops us to tier 2.
        my %off = (cache => "offline", dir => cache_dir($name, "committed"), par => 1);
        print "\n=== proof: $name  (load tier 1: offline, no solver) ===\n";
        next if run_cmd(proof_cmd($name, "prove", \%off)) == 0;   # fresh + proved

        # Tier 2 -- REPLAY: the committed cache missed, so re-derive the missed
        # goals with the solvers. Proving them now means the cache was merely STALE
        # (the proof still holds) -> advisory; failing to prove them is a real
        # REGRESSION -> hard failure. par=8 bounds the wall-clock (nothing is
        # written, so determinism is moot).
        my %rep = (cache => "replay", dir => cache_dir($name, "committed"), par => 8);
        print "\n=== proof: $name  (load tier 2: replay, re-prove on miss) ===\n";
        if (run_cmd(proof_cmd($name, "prove", \%rep)) == 0) { push @stale, $name; }
        else { push @failures, "$name/prove"; }
    } else {
        # prove / save: a single pass in the workflow's own cache mode.
        my %p = (cache => $prof->{cache},
                 dir   => cache_dir($name, $prof->{dir}),
                 par   => $prof->{par});
        print "\n=== proof: $name  (prove: cache=$p{cache}, par=$p{par}) ===\n";
        push @failures, "$name/prove" if run_cmd(proof_cmd($name, "prove", \%p)) != 0;
    }
}

# --save: the freshly written committed cache must stand ALONE -- discharge every
# goal with no solver. Re-run each proof in offline mode (never calls a solver; a
# miss is unproved, hence a hard failure) to prove the regeneration was complete.
if ($workflow eq "save" && !@failures) {
    for my $runner (@runners) {
        my $name = basename(dirname($runner));
        my %v = (cache => "offline",
                 dir   => cache_dir($name, "committed"),
                 par   => 1);
        print "\n=== proof: $name  (verify committed cache stands alone: offline) ===\n";
        push @failures, "$name/verify" if run_cmd(proof_cmd($name, "prove", \%v)) != 0;
    }
}

# --- report -----------------------------------------------------------------
if (@failures) {
    print_failure(\@failures);
    exit 1;
}
if ($workflow eq "save") {
    print "\nCommitted cache regenerated deterministically (ordered, par=1) and\n"
        . "verified to stand alone (offline replay hit every goal) in the pinned\n"
        . "container. Review and commit the updated proof/*/wp-cache/.\n";
    exit 0;
}
print_success(\@runners);
print_stale(\@stale) if @stale;
exit 0;

# ---------------------------------------------------------------------------

# Build the argv to run one proof/mode, either in the container or natively. The
# per-proof runner resolves the repo root from its own location, so cwd does not
# matter natively; in the container the repo is bind-mounted at /src and
# run_wp.sh lives at the same relative path. $prof is the cache profile (hashref
# with cache/dir/par) for 'prove', or undef for cacheless modes like check-scope.
sub proof_cmd {
    my ($name, $mode, $prof) = @_;
    my $rel = "proof/$name/run_wp.sh";
    my @env;
    if ($prof) {
        @env = ("FRAMAC_WP_CACHE=$prof->{cache}",
                "FRAMAC_WP_CACHEDIR=$prof->{dir}",
                "FRAMAC_WP_PAR=$prof->{par}");
        # Forward a per-goal timeout override into the container when set, so the
        # committed cache can be regenerated on a slow/emulated toolchain (amd64
        # image under QEMU) without false timeouts. Unset -> run_wp.sh default 30.
        push @env, "FRAMAC_WP_TIMEOUT=$ENV{FRAMAC_WP_TIMEOUT}"
            if defined $ENV{FRAMAC_WP_TIMEOUT};
    }
    if ($use_docker) {
        my @e = map { ("-e", $_) } @env;
        return ("docker", "run", "--rm",
                "-v", "$REPO_ROOT:/src", "-w", "/src",
                @e, $IMAGE, $rel, $mode);
    } else {
        for (@env) { my ($k, $v) = split /=/, $_, 2; $ENV{$k} = $v; }
        return ("$REPO_ROOT/$rel", $mode);
    }
}

# Absolute path of a proof's cache dir, as run_wp.sh will see it. Under Docker the
# repo is bind-mounted at /src; natively it is $REPO_ROOT. 'committed' is the
# checked-in wp-cache/; 'scratch' is a gitignored per-proof dir (see .gitignore).
sub cache_dir {
    my ($name, $kind) = @_;
    my $sub  = $kind eq "scratch" ? ".wp-cache-local" : "wp-cache";
    my $base = $use_docker ? "/src/proof/$name" : "$PROOF_DIR/$name";
    return "$base/$sub";
}

# Wipe a proof's committed cache so --save rebuilds it from scratch (no orphaned
# entries). Operates on the host path directly -- even under Docker the cache is a
# bind-mounted file, so there is no need to do this inside the container.
sub wipe_committed_cache {
    my ($name) = @_;
    my $dir = "$PROOF_DIR/$name/wp-cache";
    require File::Path;
    print "+ rm -rf $dir  (clean rebuild)\n";
    File::Path::remove_tree($dir) if -d $dir;
    File::Path::make_path($dir);
}

# crypto/punycode.c pulls in a chain of OpenSSL headers that are GENERATED and
# .gitignore'd -- configuration.h (via macros.h), opensslv.h (via macros.h), and
# crypto.h (via internal/e_os.h), among others. A fresh checkout (CI, or a clean
# clone) lacks them, so Frama-C's preprocessing step fails with "No such file";
# an already-configured dev tree has them. We regenerate them only when missing,
# so this never disturbs an existing local build configuration. Generation is
# perl-only -- no C compiler is needed just to produce the headers.
sub ensure_generated_headers {
    # A representative slice of the parse's generated include closure; if these
    # are present the tree is configured, and we leave it untouched.
    my @need = map { "include/openssl/$_" }
        qw(configuration.h opensslv.h crypto.h);
    return unless grep { ! -f "$REPO_ROOT/$_" } @need;

    print "=== generating OpenSSL configured headers (missing in this tree) ===\n";
    # ./Configure writes configuration.h plus configdata.pm/Makefile; running it
    # on a fresh checkout also gives the Makefile current timestamps, so the
    # follow-up 'make build_generated' produces every mandatory generated header
    # (opensslv.h, crypto.h, ...) without tripping a reconfigure. build_generated
    # is the canonical "generate all mandatory sources" target, so it stays
    # correct even if the proof's include closure grows.
    if (! -f "$REPO_ROOT/configdata.pm") {
        die "$0: ./Configure failed (needed to configure the tree)\n"
            if run_in_root("./Configure") != 0;
    }
    die "$0: 'make build_generated' failed (generating OpenSSL headers)\n"
        if run_in_root("make", "-s", "build_generated") != 0;

    for my $h (@need) {
        die "$0: generated header still missing after generation: $h\n"
            unless -f "$REPO_ROOT/$h";
    }
}

# Run a command with the repo root as cwd (Configure/make must run from there),
# restoring the previous cwd afterwards. Returns the child's exit code.
sub run_in_root {
    my @cmd = @_;
    my $save = getcwd();
    chdir($REPO_ROOT) or die "$0: chdir $REPO_ROOT: $!\n";
    my $rc = run_cmd(@cmd);
    chdir($save)      or die "$0: chdir back to $save: $!\n";
    return $rc;
}

# system() wrapper returning the child's exit code (or non-zero on spawn/signal).
sub run_cmd {
    my @cmd = @_;
    print "+ @cmd\n";
    my $status = system(@cmd);
    return exit_code($status, $cmd[0]);
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

  punycode (ossl_a2ulabel + its in-tree call tree in crypto/punycode.c):
    * TRUST BASE: two sets of assumed contracts --
        - a libc memmove of 4k bytes behaves as an element-wise move of k uint32s
          (WP's typed memory model cannot relate byte-wise memmove to the uint32
          buffer; -instantiate relocates the gap into memmove_uint's assigns);
        - the WPACKET functions (init/memcpy/put_bytes/cleanup), whose bodies are
          in crypto/packet.c outside this TU: their contracts in
          proof/punycode/wpacket_spec.h are ASSUMED and hand-audited against
          packet.c, not proved here.
    * CALLER OBLIGATIONS of ossl_a2ulabel (the requires, discharged onto callers):
        - in is a NUL-terminated string with strlen(in) <= PTRDIFF_MAX;
        - out[0 .. outlen-1] is valid and does not overlap in.
      (ossl_punycode_decode's old requires are now discharged INTERNALLY at the
      call site -- in particular the latent divide-by-zero is proved unreachable
      through this caller, which never offers decode a UINT_MAX-sized buffer.)
    * SCOPE: this proves ossl_a2ulabel -- the WPACKET-based caller that actually
      held CVE-2022-3786 -- together with ossl_punycode_decode (CVE-2022-3602) and
      every other in-tree function reachable from it. The check-scope guard, with
      its MUST_COVER floor, confirms no reachable in-tree callee slipped outside
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

Note: a merely STALE committed cache is NOT a failure -- under --load (replay) the
solvers re-derive any missed goals live, so an out-of-date cache still PASSES with
an advisory to regenerate it (./proof/run_proofs.pl --save). A failure here means
the proof genuinely did not go through; regenerating the cache will not fix it.

If you changed crypto/punycode.c and cannot work out how to repair the proof,
the point of contact is $CONTACT -- reach out and I will help.
============================================================================
EOF
}

sub print_stale {
    my ($stale) = @_;
    print <<"EOF";

============================================================================
PROOFS PASSED, COMMITTED CACHE STALE (advisory): @$stale

Every verification obligation was discharged -- the proof still HOLDS -- but the
committed proof cache (proof/*/wp-cache/) no longer matches the current goals, so
the solvers had to re-derive the missed goals live instead of replaying them from
the cache. That is slower and, on a loaded runner, marginally more prone to a
false timeout. It is NOT a proof failure.

This usually means the proved source (e.g. crypto/punycode.c) or its ACSL
annotations changed in a way that shifts the WP goals, without the cache being
regenerated. To refresh it, run in the pinned container and commit the result:
    ./proof/run_proofs.pl --save

If you are a contributor who did not intend to touch the proof, the point of
contact is $CONTACT.
============================================================================
EOF
}
