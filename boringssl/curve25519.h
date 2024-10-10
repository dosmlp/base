/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_CURVE25519_H
#define OPENSSL_HEADER_CURVE25519_H

#include <stdint.h>
#include <memory.h>

// me
#include "target.h"
#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_SMALL) && \
defined(__GNUC__) && defined(__x86_64__) && !defined(OPENSSL_WINDOWS)
#define BORINGSSL_FE25519_ADX
// fiat_curve25519_adx_mul is defined in
// third_party/fiat/asm/fiat_curve25519_adx_mul.S
void __attribute__((sysv_abi))
fiat_curve25519_adx_mul(uint64_t out[4], const uint64_t in1[4],
                        const uint64_t in2[4]);

// fiat_curve25519_adx_square is defined in
// third_party/fiat/asm/fiat_curve25519_adx_square.S
void __attribute__((sysv_abi))
fiat_curve25519_adx_square(uint64_t out[4], const uint64_t in[4]);

// x25519_scalar_mult_adx is defined in third_party/fiat/curve25519_64_adx.h
void x25519_scalar_mult_adx(uint8_t out[32], const uint8_t scalar[32],
                            const uint8_t point[32]);
void x25519_ge_scalarmult_base_adx(uint8_t h[4][32], const uint8_t a[32]);
#endif

#if defined(OPENSSL_ARM) && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_APPLE)
#define BORINGSSL_X25519_NEON

// x25519_NEON is defined in asm/x25519-arm.S.
void x25519_NEON(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32]);
#endif
static inline uint64_t CRYPTO_load_u64_le(const void *in) {
    uint64_t v;
    memcpy(&v, in, sizeof(v));
    return v;
}
//end me
#if defined(__cplusplus)
extern "C" {
#endif


// Curve25519.
//
// Curve25519 is an elliptic curve. See https://tools.ietf.org/html/rfc7748.


// X25519.
//
// X25519 is the Diffie-Hellman primitive built from curve25519. It is
// sometimes referred to as “curve25519”, but “X25519” is a more precise name.
// See http://cr.yp.to/ecdh.html and https://tools.ietf.org/html/rfc7748.

#define X25519_PRIVATE_KEY_LEN 32
#define X25519_PUBLIC_VALUE_LEN 32
#define X25519_SHARED_KEY_LEN 32

// X25519_keypair sets |out_public_value| and |out_private_key| to a freshly
// generated, public–private key pair.
void X25519_keypair(uint8_t out_public_value[32],
                                   uint8_t out_private_key[32]);

// X25519 writes a shared key to |out_shared_key| that is calculated from the
// given private key and the peer's public value. It returns one on success and
// zero on error.
//
// Don't use the shared key directly, rather use a KDF and also include the two
// public values as inputs.
int X25519(uint8_t out_shared_key[32],
                          const uint8_t private_key[32],
                          const uint8_t peer_public_value[32]);

// X25519_public_from_private calculates a Diffie-Hellman public value from the
// given private key and writes it to |out_public_value|.
void X25519_public_from_private(uint8_t out_public_value[32],
                                               const uint8_t private_key[32]);


// Ed25519.
//
// Ed25519 is a signature scheme using a twisted-Edwards curve that is
// birationally equivalent to curve25519.
//
// Note that, unlike RFC 8032's formulation, our private key representation
// includes a public key suffix to make multiple key signing operations with the
// same key more efficient. The RFC 8032 private key is referred to in this
// implementation as the "seed" and is the first 32 bytes of our private key.

#define ED25519_PRIVATE_KEY_LEN 64
#define ED25519_PUBLIC_KEY_LEN 32
#define ED25519_SIGNATURE_LEN 64

// ED25519_keypair sets |out_public_key| and |out_private_key| to a freshly
// generated, public–private key pair.
void ED25519_keypair(uint8_t out_public_key[32],
                                    uint8_t out_private_key[64]);

// ED25519_sign sets |out_sig| to be a signature of |message_len| bytes from
// |message| using |private_key|. It returns one on success or zero on
// allocation failure.
int ED25519_sign(uint8_t out_sig[64], const uint8_t *message,
                                size_t message_len,
                                const uint8_t private_key[64]);

// ED25519_verify returns one iff |signature| is a valid signature, by
// |public_key| of |message_len| bytes from |message|. It returns zero
// otherwise.
int ED25519_verify(const uint8_t *message, size_t message_len,
                                  const uint8_t signature[64],
                                  const uint8_t public_key[32]);

// ED25519_keypair_from_seed calculates a public and private key from an
// Ed25519 “seed”. Seed values are not exposed by this API (although they
// happen to be the first 32 bytes of a private key) so this function is for
// interoperating with systems that may store just a seed instead of a full
// private key.
void ED25519_keypair_from_seed(uint8_t out_public_key[32],
                                              uint8_t out_private_key[64],
                                              const uint8_t seed[32]);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CURVE25519_H
