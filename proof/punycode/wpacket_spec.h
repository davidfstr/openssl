/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * wpacket_spec.h -- TRUST-BASE ACSL contracts for the WPACKET functions
 * ossl_a2ulabel (crypto/punycode.c) calls.
 *
 * The bodies live in crypto/packet.c, OUTSIDE the punycode proof's translation
 * unit, so WP ASSUMES these contracts; nothing checks them against the bodies.
 * Every clause below was derived by hand from crypto/packet.c and must be
 * re-audited if packet.c changes. They are part of the proof's trust base,
 * exactly like the libc contracts -- see proof/README.md.
 *
 * Injected via -cpp-extra-args="-include wpacket_spec.h": Frama-C attaches a
 * contract written on ANY declaration of a function to the function itself,
 * so annotated re-declarations here merge with the bare ones the TU later
 * pulls in from internal/packet.h.
 *
 * SCOPE OF VALIDITY. These contracts describe WPACKET only as ossl_a2ulabel
 * configures it, which wpacket_static_inv pins down:
 *   - fixed static buffer (staticbuf != NULL, buf == NULL: no BUF_MEM growth)
 *   - no length-prefix bytes (init lenbytes == 0 is a requires)
 *   - forward writing (endfirst == 0), no sub-packets beyond the root
 * In that configuration WPACKET degenerates to a bounds-checked bump-pointer
 * writer: an append of len bytes succeeds iff len <= maxsize - written
 * (WPACKET_reserve_bytes; this test is what stops the CVE-2022-3786 class),
 * advances curr == written by exactly len, and on failure changes nothing.
 * The failure-preserves-state clauses matter because ossl_a2ulabel keeps
 * appending after a failed (result = 0) append.
 *
 * Residual assumptions NOT expressible in the contracts:
 *   - init's OPENSSL_zalloc of the root WPACKET_SUB (WP cannot model
 *     allocation; "assigns *pkt" hides the fresh heap node) and cleanup's
 *     OPENSSL_free of that chain (touches only nodes init/sub-packet calls
 *     allocated, never staticbuf).
 *   - the Typed+cast memory model assumes pointer casts preserve layout; all
 *     casts this proof relies on are char* <-> unsigned char*.
 */

#include "internal/packet.h"

/*
 * The state ossl_a2ulabel's pkt satisfies between WPACKET calls, from
 * successful init until cleanup. written <= maxsize and the buffer validity
 * are what make each append's staticbuf[written ..] write safe.
 */
/*@ predicate wpacket_static_inv(WPACKET *pkt) =
      \valid(pkt) &&
      pkt->staticbuf != \null && pkt->buf == \null &&
      pkt->subs != \null &&
      pkt->endfirst == 0 &&
      pkt->curr == pkt->written &&
      pkt->written <= pkt->maxsize &&
      \valid(pkt->staticbuf + (0 .. pkt->maxsize - 1));
*/

/*@ requires \valid(pkt);
    requires \valid(buf + (0 .. len - 1));
    requires lenbytes == 0;
    assigns *pkt;
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==>
        wpacket_static_inv(pkt) &&
        pkt->staticbuf == buf && pkt->written == 0 && pkt->maxsize == len;
*/
int WPACKET_init_static_len(WPACKET *pkt, unsigned char *buf, size_t len,
    size_t lenbytes);

/*@ requires wpacket_static_inv(pkt);
    requires \valid_read((unsigned char *)src + (0 .. len - 1));
    assigns pkt->curr, pkt->written,
        pkt->staticbuf[pkt->written .. pkt->written + len - 1];
    ensures wpacket_static_inv(pkt);
    ensures pkt->staticbuf == \old(pkt->staticbuf);
    ensures pkt->maxsize == \old(pkt->maxsize);
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> pkt->written == \old(pkt->written) + len;
    ensures \result == 0 ==> pkt->written == \old(pkt->written);
*/
int WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len);

/* Only the WPACKET_put_bytes_u8 (bytes == 1) instantiation is in scope. */
/*@ requires wpacket_static_inv(pkt);
    assigns pkt->curr, pkt->written,
        pkt->staticbuf[pkt->written .. pkt->written + bytes - 1];
    ensures wpacket_static_inv(pkt);
    ensures pkt->staticbuf == \old(pkt->staticbuf);
    ensures pkt->maxsize == \old(pkt->maxsize);
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> pkt->written == \old(pkt->written) + bytes;
    ensures \result == 0 ==> pkt->written == \old(pkt->written);
*/
int WPACKET_put_bytes__(WPACKET *pkt, uint64_t val, size_t bytes);

/*@ requires \valid(pkt);
    assigns pkt->subs;
    ensures pkt->subs == \null;
*/
void WPACKET_cleanup(WPACKET *pkt);
