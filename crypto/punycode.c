/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/e_os2.h>
#include "crypto/punycode.h"
#include "internal/common.h" /* for ossl_assert */
#include "internal/packet.h" /* for WPACKET */

static const unsigned int base = 36;
static const unsigned int tmin = 1;
static const unsigned int tmax = 26;
static const unsigned int skew = 38;
static const unsigned int damp = 700;
static const unsigned int initial_bias = 72;
static const unsigned int initial_n = 0x80;
static const unsigned int maxint = 0xFFFFFFFF;
static const char delimiter = '-';

#define LABEL_BUF_SIZE 512

/*
 * Computes a new "bias" value, which is a logarithm-like measure of the most
 * recent "delta"'s magnitude.
 */
/*-
 * Pseudocode:
 *
 * function adapt(delta,numpoints,firsttime):
 *  if firsttime then let delta = delta div damp
 *  else let delta = delta div 2
 *  let delta = delta + (delta div numpoints)
 *  let k = 0
 *  while delta > ((base - tmin) * tmax) div 2 do begin
 *    let delta = delta div (base - tmin)
 *    let k = k + base
 *  end
 *  return k + (((base - tmin + 1) * delta) div (delta + skew))
 */
/*@ requires numpoints >= 1;
    assigns \nothing;
*/
static int adapt(unsigned int delta, unsigned int numpoints,
    unsigned int firsttime)
{
    unsigned int k = 0;

    delta = (firsttime) ? delta / damp : delta / 2;
    delta = delta + delta / numpoints;

    /*@ loop assigns delta, k;
        loop variant delta;
    */
    while (delta > ((base - tmin) * tmax) / 2) {
        delta = delta / (base - tmin);
        k = k + base;
    }

    return k + (((base - tmin + 1) * delta) / (delta + skew));
}

/*@ assigns \nothing; */
static ossl_inline int is_basic(unsigned int a)
{
    return (a < 0x80) ? 1 : 0;
}

/*-
 * code points    digit-values
 * ------------   ----------------------
 * 41..5A (A-Z) =  0 to 25, respectively
 * 61..7A (a-z) =  0 to 25, respectively
 * 30..39 (0-9) = 26 to 35, respectively
 */
/*@ assigns \nothing; */
static ossl_inline int digit_decoded(const unsigned char a)
{
    if (a >= 0x41 && a <= 0x5A)
        return a - 0x41;

    if (a >= 0x61 && a <= 0x7A)
        return a - 0x61;

    if (a >= 0x30 && a <= 0x39)
        return a - 0x30 + 26;

    return -1;
}

/*-
 * Decodes a buffer of Punycode bytes (pEncoded, length enc_len) to a
 * UTF-32 buffer (pDecoded, capacity *pout_length). Returns 1 on success,
 * else 0. On success stores the length of the decoded UTF-32 string in
 * *pout_length.
 *
 * Examples:
 * - "" -> ""                   (empty string)
 * - "a-" -> U"a"               (only ASCII codepoints)
 * - "Mnchen-3ya" -> U"München" (1 non-ASCII codepoint; rest are ASCII)
 * - "mxacd" -> U"αβγ"          (all non-ASCII codepoints)
 *
 * Special preconditions:
 * - The caller MUST ensure (enc_len <= UINT_MAX) so that this function
 *   terminates.
 * - The caller MUST ensure (*pout_length < UINT_MAX) to avoid a divide-by-zero.
 */
/*-
 * Pseudocode:
 *
 * function ossl_punycode_decode
 *  let n = initial_n
 *  let i = 0
 *  let bias = initial_bias
 *  let output = an empty string indexed from 0
 *  consume all code points before the last delimiter (if there is one)
 *    and copy them to output, fail on any non-basic code point
 *  if more than zero code points were consumed then consume one more
 *    (which will be the last delimiter)
 *  while the input is not exhausted do begin
 *    let oldi = i
 *    let w = 1
 *    for k = base to infinity in steps of base do begin
 *      consume a code point, or fail if there was none to consume
 *      let digit = the code point's digit-value, fail if it has none
 *      let i = i + digit * w, fail on overflow
 *      let t = tmin if k <= bias {+ tmin}, or
 *              tmax if k >= bias + tmax, or k - bias otherwise
 *      if digit < t then break
 *      let w = w * (base - t), fail on overflow
 *    end
 *    let bias = adapt(i - oldi, length(output) + 1, test oldi is 0?)
 *    let n = n + i div (length(output) + 1), fail on overflow
 *    let i = i mod (length(output) + 1)
 *    {if n is a basic code point then fail}
 *    insert n into output at position i
 *    increment i
 *  end
 */
/*@ requires enc_len >= 0;
    requires enc_len <= UINT_MAX;
    requires \valid_read(pEncoded + (0 .. enc_len - 1));
    requires \valid(pout_length);
    requires *pout_length >= 0;
    requires *pout_length < UINT_MAX;
    requires \valid(pDecoded + (0 .. *pout_length - 1));
    requires \separated(pout_length, pDecoded + (0 .. *pout_length - 1));
    assigns *pout_length, pDecoded[0 .. *pout_length - 1];
    ensures *pout_length <= \old(*pout_length);
*/
int ossl_punycode_decode(const char *pEncoded, const size_t enc_len,
    unsigned int *pDecoded, unsigned int *pout_length)
{
    unsigned int n = initial_n;
    unsigned int i = 0;
    unsigned int bias = initial_bias;
    unsigned int processed_in = 0;
    unsigned int written_out = 0;
    unsigned int max_out = *pout_length;
    unsigned int basic_count = 0;
    unsigned int loop;

    if (enc_len >= UINT_MAX)
        return 0;

    /*
     * Search for the last '-' delimiter, storing the number of
     * probably-ASCII codepoints preceding the dash in basic_count, or 0 if
     * the dash was not found.
     */
    /*@ loop invariant 0 <= loop <= enc_len;
        loop invariant
            (basic_count == enc_len == 0) ||
            (0 <= basic_count < enc_len);
        loop assigns loop, basic_count;
        loop variant enc_len - loop;
    */
    for (loop = 0; loop < (unsigned int)enc_len; loop++) {
        if (pEncoded[loop] == delimiter)
            basic_count = loop;
    }
    /*@ assert
            (basic_count == enc_len == 0) ||
            (0 <= basic_count < enc_len);
    */

    /* Copy leading ASCII codepoints from input to output buffer, if any. */
    if (basic_count > 0) {
        /*@ assert 0 <= basic_count < enc_len; */

        if (basic_count > max_out)
            return 0;

        /*
         * 1. Verify that all codepoints preceding the last dash are ASCII.
         * 2. Copy those ASCII codepoints from input to output buffer.
         */
        /*@ loop invariant 0 <= loop <= basic_count;
            loop invariant written_out == loop;
            loop assigns loop, written_out, pDecoded[0 .. basic_count - 1];
            loop variant basic_count - loop;
        */
        for (loop = 0; loop < basic_count; loop++) {
            if (is_basic(pEncoded[loop]) == 0)
                return 0;

            pDecoded[loop] = pEncoded[loop];
            written_out++;
        }
        processed_in = basic_count + 1;
    }
    /*@ assert 0 <= processed_in <= enc_len; */
    /*@ assert (written_out == 0) || (written_out == basic_count); */

    /* Insert each decoded non-ASCII codepoint into output buffer */
    /*@ loop invariant processed_in <= loop <= enc_len;
        loop invariant (written_out == 0) || (0 <= written_out <= max_out);
        loop assigns loop, i, bias, n, pDecoded[0 .. max_out - 1], written_out;
        loop variant enc_len - loop;
    */
    for (loop = processed_in; loop < (unsigned int)enc_len;) {
        unsigned int oldi = i;
        unsigned int w = 1;
        unsigned int k, t;
        int digit;

        /* Decode a "delta" variable-length integer (i - oldi) */
        /*@ loop invariant processed_in <= loop <= enc_len;
            loop invariant w >= 1;
            loop invariant loop >= \at(loop, LoopEntry);
            loop assigns k, digit, loop, i, t, w;
            loop variant enc_len - loop;
        */
        for (k = base;; k += base) {
            if (loop >= enc_len)
                return 0;
            /*@ assert 0 <= processed_in <= loop < enc_len; */

            digit = digit_decoded(pEncoded[loop]);
            loop++;

            if (digit < 0)
                return 0;
            if ((unsigned int)digit > (maxint - i) / w)
                return 0;

            i = i + digit * w;
            t = (k <= bias) ? tmin : (k >= bias + tmax) ? tmax
                                                        : k - bias;
            /*@ assert tmin <= t <= tmax; */

            if ((unsigned int)digit < t)
                break;

            /*@ assert (base - t) > 0; */
            if (w > maxint / (base - t))
                return 0;
            /*@ assert w * (base - t) <= maxint; */
            w = w * (base - t);
        }

        /* Compute a new "bias" value, based on the last "delta" (i - oldi) */
        /*@ assert written_out + 1 <= UINT_MAX; */
        bias = adapt(i - oldi, written_out + 1, (oldi == 0));
        /* Compute codepoint to insert: n */
        if (i / (written_out + 1) > maxint - n)
            return 0;
        n = n + i / (written_out + 1);
        /* Compute index to insert at: i */
        i %= (written_out + 1);
        /*@ assert 0 <= i <= written_out; */

        /* Fail if inserting a codepoint would overflow output capacity */
        if (written_out >= max_out)
            return 0;
        /*@ assert written_out < max_out; */

        /* Insert codepoint n at index i, shifting old ones to the right */
        /*@ assert 0 <= i < max_out; */
        memmove(pDecoded + i + 1, pDecoded + i,
            (written_out - i) * sizeof(*pDecoded));
        pDecoded[i] = n;
        i++;
        written_out++;
    }

    *pout_length = written_out;
    return 1;
}

/*
 * Encode a code point using UTF-8
 * return number of bytes on success, 0 on failure
 * (also produces U+FFFD, which uses 3 bytes on failure)
 */
/*@ requires \valid(out + (0 .. 4));
    assigns out[0 .. 4];
    ensures 0 <= \result <= 4;
*/
static int codepoint2utf8(unsigned char *out, unsigned long utf)
{
    if (utf <= 0x7F) {
        /* Plain ASCII */
        out[0] = (unsigned char)utf;
        out[1] = 0;
        return 1;
    } else if (utf <= 0x07FF) {
        /* 2-byte unicode */
        out[0] = (unsigned char)(((utf >> 6) & 0x1F) | 0xC0);
        out[1] = (unsigned char)(((utf >> 0) & 0x3F) | 0x80);
        out[2] = 0;
        return 2;
    } else if (utf <= 0xFFFF) {
        /* 3-byte unicode */
        out[0] = (unsigned char)(((utf >> 12) & 0x0F) | 0xE0);
        out[1] = (unsigned char)(((utf >> 6) & 0x3F) | 0x80);
        out[2] = (unsigned char)(((utf >> 0) & 0x3F) | 0x80);
        out[3] = 0;
        return 3;
    } else if (utf <= 0x10FFFF) {
        /* 4-byte unicode */
        out[0] = (unsigned char)(((utf >> 18) & 0x07) | 0xF0);
        out[1] = (unsigned char)(((utf >> 12) & 0x3F) | 0x80);
        out[2] = (unsigned char)(((utf >> 6) & 0x3F) | 0x80);
        out[3] = (unsigned char)(((utf >> 0) & 0x3F) | 0x80);
        out[4] = 0;
        return 4;
    } else {
        /* error - use replacement character */
        out[0] = (unsigned char)0xEF;
        out[1] = (unsigned char)0xBF;
        out[2] = (unsigned char)0xBD;
        out[3] = 0;
        return 0;
    }
}

static const char XN_PREFIX[] = "xn--";

/*-
 * Return values:
 * 1 - ok
 * 0 - ok but buf was too short
 * -1 - bad string passed or other error
 */
/*@ requires valid_read_string(in);
    requires strlen(in) <= PTRDIFF_MAX; // needed for: tmpptr - inptr
    requires \valid(out + (0 .. outlen - 1));
    requires \separated(in + (0 .. strlen(in)), out + (0 .. outlen - 1));
    exits \true; // no guarantees declared upon exit
*/
int ossl_a2ulabel(const char *in, char *out, size_t outlen)
{
    /*-
     * Domain name has some parts consisting of ASCII chars joined with dot.
     * If a part is shorter than 5 chars, it becomes U-label as is.
     * If it does not start with xn--,    it becomes U-label as is.
     * Otherwise we try to decode it.
     */
    const char *inptr = in;
    int result = 1;
    unsigned int i;
    unsigned int buf[LABEL_BUF_SIZE]; /* It's a hostname */
    WPACKET pkt;

    /* Internal API, so should not fail */
    if (!ossl_assert(out != NULL))
        return -1;

    if (!WPACKET_init_static_len(&pkt, (unsigned char *)out, outlen, 0))
        return -1;

    while (1) {
        const char *tmpptr = strchr(inptr, '.');
        size_t delta = tmpptr != NULL ? (size_t)(tmpptr - inptr) : strlen(inptr);

        /* if (!HAS_PREFIX(inptr, "xn--")): Proofs have difficulty reasoning
         * about string literals. So "xn--" is assigned to XN_PREFIX and the
         * HAS_PREFIX macro is expanded manually. */
        if (strncmp(inptr, XN_PREFIX, sizeof(XN_PREFIX) - 1) != 0) {
            if (!WPACKET_memcpy(&pkt, inptr, delta))
                result = 0;
        } else {
            unsigned int bufsize = LABEL_BUF_SIZE;

            /*
             * The label starts with "xn--", and '.' does not occur in that
             * prefix, so the '.' (or NUL) that defined delta lies at or
             * beyond inptr + 4: the decode call below stays inside the label.
             */
            /* TODO: Check whether any of the following asserts are unnecessary */
            /*@ assert stones: inptr[0] == 'x' && inptr[1] == 'n'
                    && inptr[2] == '-' && inptr[3] == '-'; */
            /*@ assert nodot: \forall integer j; 0 <= j < 4 ==> inptr[j] != '.'; */
            /*@ assert len4: strlen(inptr) >= 4; */
            /*@ assert dot_at: tmpptr != \null ==> *tmpptr == '.'; */
            /*@ assert far: tmpptr != \null ==> tmpptr - inptr >= 4; */
            /*@ assert delta4: delta >= 4; */

            if (ossl_punycode_decode(inptr + 4, delta - 4, buf, &bufsize) <= 0) {
                result = -1;
                goto end;
            }

            for (i = 0; i < bufsize; i++) {
                unsigned char seed[6];
                size_t utfsize = codepoint2utf8(seed, buf[i]);

                if (utfsize == 0) {
                    result = -1;
                    goto end;
                }

                if (!WPACKET_memcpy(&pkt, seed, utfsize))
                    result = 0;
            }
        }

        if (tmpptr == NULL)
            break;

        if (!WPACKET_put_bytes_u8(&pkt, '.'))
            result = 0;

        inptr = tmpptr + 1;
    }

    if (!WPACKET_put_bytes_u8(&pkt, '\0'))
        result = 0;
end:
    WPACKET_cleanup(&pkt);
    return result;
}
