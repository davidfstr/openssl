# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Pinned toolchain for the Frama-C/WP proofs under proof/ (see proof/README.md).
# Everything a proof depends on is version-pinned here so a run is reproducible
# and cannot silently drift: a proof that is green today stays green (or fails
# loudly) regardless of what the upstream package repos do later.
#
# The official Frama-C image already provides Frama-C 31.0 + Alt-Ergo 2.5.4 (in
# an opam 4.14 switch; its entrypoint is "opam exec --"). We add Z3 and cvc5 so
# WP's prover portfolio (alt-ergo,z3,cvc5) is complete -- no single solver closes
# every goal (see proof/punycode/run_wp.sh for the per-goal solver matrix).
#
# Base is Debian 12 "bookworm" (glibc 2.36), so the Z3 build must target glibc
# <= 2.36; 4.13.4's x64-glibc-2.35 build is the pin. cvc5 ships a fully-static
# binary, so its glibc is irrelevant. Z3 4.13.x is also a why3-recognised version
# (why3 2.x's driver regex tops out at 4.13), so WP drives it with its proper
# driver rather than a fallback.
#
# Pin the base by digest, not just the tag, so the exact image is fixed:
#   framac/frama-c:31.0.debian  (linux/amd64)
FROM framac/frama-c:31.0.debian@sha256:ea473030403b3fe0f55858fc47a3c212d2c46b405492eb8c3599351d0f0cbc7f

# --- Add pinned SMT solvers (Z3, cvc5) alongside the image's Alt-Ergo. ---
ARG Z3_VER=4.13.4
ARG Z3_ZIP=z3-4.13.4-x64-glibc-2.35.zip
ARG Z3_SHA256=93f91f9c6f4a00a041c19fc7a74adc1f441c8244ce70d486e19abcd89c6a014b
ARG CVC5_VER=1.3.4
ARG CVC5_ZIP=cvc5-Linux-x86_64-static.zip
ARG CVC5_SHA256=dcdbfada0ce493ee98259c0816e0daafc561c223aadb3af298c2968e73ea39c6

USER root
RUN set -eux; \
    cd /tmp; \
    curl -fsSL -o z3.zip \
        "https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VER}/${Z3_ZIP}"; \
    echo "${Z3_SHA256}  z3.zip" | sha256sum -c -; \
    unzip -q z3.zip; \
    install -m0755 "z3-${Z3_VER}-x64-glibc-2.35/bin/z3" /usr/local/bin/z3; \
    curl -fsSL -o cvc5.zip \
        "https://github.com/cvc5/cvc5/releases/download/cvc5-${CVC5_VER}/${CVC5_ZIP}"; \
    echo "${CVC5_SHA256}  cvc5.zip" | sha256sum -c -; \
    unzip -q cvc5.zip; \
    install -m0755 "cvc5-Linux-x86_64-static/bin/cvc5" /usr/local/bin/cvc5; \
    rm -rf /tmp/z3.zip /tmp/cvc5.zip "/tmp/z3-${Z3_VER}-x64-glibc-2.35" \
        /tmp/cvc5-Linux-x86_64-static; \
    z3 --version; \
    cvc5 --version | head -1

# Register the new solvers with why3 (Frama-C/WP dispatches provers through
# why3), then confirm WP can see all three. Run as the image's opam user so the
# config lands in that user's home, which is who run_proofs.pl runs as.
USER opam
RUN set -eux; \
    opam exec -- why3 config detect; \
    opam exec -- frama-c -wp-detect | grep -q 'Alt-Ergo 2'; \
    opam exec -- frama-c -wp-detect | grep -q 'Z3 4.13'; \
    opam exec -- frama-c -wp-detect | grep -q 'CVC5'
