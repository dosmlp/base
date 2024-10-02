/* Copyright (c) 2020, Google Inc.
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

#ifndef OPENSSL_HEADER_CURVE25519_INTERNAL_H
#define OPENSSL_HEADER_CURVE25519_INTERNAL_H

#include "../../curve25519.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(OPENSSL_ARM) && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_APPLE)
#define BORINGSSL_X25519_NEON

// x25519_NEON is defined in asm/x25519-arm.S.
void x25519_NEON(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32]);
#endif

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

#if defined(OPENSSL_64_BIT)
// fe means field element. Here the field is \Z/(2^255-19). An element t,
// entries t[0]...t[4], represents the integer t[0]+2^51 t[1]+2^102 t[2]+2^153
// t[3]+2^204 t[4].
// fe limbs are bounded by 1.125*2^51.
// Multiplication and carrying produce fe from fe_loose.
typedef struct fe { uint64_t v[5]; } fe;

// fe_loose limbs are bounded by 3.375*2^51.
// Addition and subtraction produce fe_loose from (fe, fe).
typedef struct fe_loose { uint64_t v[5]; } fe_loose;
#else
// fe means field element. Here the field is \Z/(2^255-19). An element t,
// entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
// t[3]+2^102 t[4]+...+2^230 t[9].
// fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
// Multiplication and carrying produce fe from fe_loose.
typedef struct fe { uint32_t v[10]; } fe;

// fe_loose limbs are bounded by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc.
// Addition and subtraction produce fe_loose from (fe, fe).
typedef struct fe_loose { uint32_t v[10]; } fe_loose;
#endif

// ge means group element.
//
// Here the group is the set of pairs (x,y) of field elements (see fe.h)
// satisfying -x^2 + y^2 = 1 + d x^2y^2
// where d = -121665/121666.
//
// Representations:
//   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   ge_precomp (Duif): (y+x,y-x,2dxy)

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe_loose X;
  fe_loose Y;
  fe_loose Z;
  fe_loose T;
} ge_p1p1;

typedef struct {
  fe_loose yplusx;
  fe_loose yminusx;
  fe_loose xy2d;
} ge_precomp;

typedef struct {
  fe_loose YplusX;
  fe_loose YminusX;
  fe_loose Z;
  fe_loose T2d;
} ge_cached;

void x25519_ge_tobytes(uint8_t s[32], const ge_p2 *h);
int x25519_ge_frombytes_vartime(ge_p3 *h, const uint8_t s[32]);
void x25519_ge_p3_to_cached(ge_cached *r, const ge_p3 *p);
void x25519_ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p);
void x25519_ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p);
void x25519_ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void x25519_ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void x25519_ge_scalarmult_small_precomp(
    ge_p3 *h, const uint8_t a[32], const uint8_t precomp_table[15 * 2 * 32]);
void x25519_ge_scalarmult_base(ge_p3 *h, const uint8_t a[32]);
void x25519_ge_scalarmult(ge_p2 *r, const uint8_t *scalar, const ge_p3 *A);
void x25519_sc_reduce(uint8_t s[64]);

enum spake2_state_t {
  spake2_state_init = 0,
  spake2_state_msg_generated,
  spake2_state_key_generated,
};

struct spake2_ctx_st {
  uint8_t private_key[32];
  uint8_t my_msg[32];
  uint8_t password_scalar[32];
  uint8_t password_hash[64];
  uint8_t *my_name;
  size_t my_name_len;
  uint8_t *their_name;
  size_t their_name_len;
  enum spake2_role_t my_role;
  enum spake2_state_t state;
  char disable_password_scalar_hack;
};


extern const uint8_t k25519Precomp[32][8][3][32];

// crypto_word_t is the type that most constant-time functions use. Ideally we
// would like it to be |size_t|, but NaCl builds in 64-bit mode with 32-bit
// pointers, which means that |size_t| can be 32 bits when |BN_ULONG| is 64
// bits. Since we want to be able to do constant-time operations on a
// |BN_ULONG|, |crypto_word_t| is defined as an unsigned value with the native
// word length.
#if defined(OPENSSL_64_BIT)
typedef uint64_t crypto_word_t;
#elif defined(OPENSSL_32_BIT)
typedef uint32_t crypto_word_t;
#else
#error "Must define either OPENSSL_32_BIT or OPENSSL_64_BIT"
#endif
// |value_barrier_u8| could be defined as above, but compilers other than
// clang seem to still materialize 0x00..00MM instead of reusing 0x??..??MM.

// constant_time_msb_w returns the given value with the MSB copied to all the
// other bits.
static inline crypto_word_t constant_time_msb_w(crypto_word_t a) {
    return 0u - (a >> (sizeof(a) * 8 - 1));
}
// constant_time_is_zero returns 0xff..f if a == 0 and 0 otherwise.
static inline crypto_word_t constant_time_is_zero_w(crypto_word_t a) {
    // Here is an SMT-LIB verification of this formula:
    //
    // (define-fun is_zero ((a (_ BitVec 32))) (_ BitVec 32)
    //   (bvand (bvnot a) (bvsub a #x00000001))
    // )
    //
    // (declare-fun a () (_ BitVec 32))
    //
    // (assert (not (= (= #x00000001 (bvlshr (is_zero a) #x0000001f)) (= a #x00000000))))
    // (check-sat)
    // (get-model)
    return constant_time_msb_w(~a & (a - 1));
}

// constant_time_is_zero_8 acts like |constant_time_is_zero_w| but returns an
// 8-bit mask.
static inline uint8_t constant_time_is_zero_8(crypto_word_t a) {
    return (uint8_t)(constant_time_is_zero_w(a));
}

// constant_time_eq_w returns 0xff..f if a == b and 0 otherwise.
static inline crypto_word_t constant_time_eq_w(crypto_word_t a,
                                               crypto_word_t b) {
    return constant_time_is_zero_w(a ^ b);
}
// value_barrier_w returns |a|, but prevents GCC and Clang from reasoning about
// the returned value. This is used to mitigate compilers undoing constant-time
// code, until we can express our requirements directly in the language.
//
// Note the compiler is aware that |value_barrier_w| has no side effects and
// always has the same output for a given input. This allows it to eliminate
// dead code, move computations across loops, and vectorize.
static inline crypto_word_t value_barrier_w(crypto_word_t a) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(a) : /* no inputs */);
#endif
    return a;
}
// buffers_alias returns one if |a| and |b| alias and zero otherwise.
static inline int buffers_alias(const void *a, size_t a_bytes,
                                const void *b, size_t b_bytes) {
    // Cast |a| and |b| to integers. In C, pointer comparisons between unrelated
    // objects are undefined whereas pointer to integer conversions are merely
    // implementation-defined. We assume the implementation defined it in a sane
    // way.
    uintptr_t a_u = (uintptr_t)a;
    uintptr_t b_u = (uintptr_t)b;
    return a_u + a_bytes > b_u && b_u + b_bytes > a_u;
}
// constant_time_conditional_memxor xors |n| bytes from |src| to |dst| if
// |mask| is 0xff..ff and does nothing if |mask| is 0. The |n|-byte memory
// ranges at |dst| and |src| must not overlap, as when calling |memcpy|.
static inline void constant_time_conditional_memxor(void *dst, const void *src,
                                                    size_t n,
                                                    const crypto_word_t mask) {
    assert(!buffers_alias(dst, n, src, n));
    uint8_t *out = (uint8_t *)dst;
    const uint8_t *in = (const uint8_t *)src;
#if defined(__GNUC__) && !defined(__clang__)
    // gcc 13.2.0 doesn't automatically vectorize this loop regardless of barrier
    typedef uint8_t v32u8 __attribute__((vector_size(32), aligned(1), may_alias));
    size_t n_vec = n&~(size_t)31;
    v32u8 masks = ((uint8_t)mask-(v32u8){}); // broadcast
    for (size_t i = 0; i < n_vec; i += 32) {
        *(v32u8*)&out[i] ^= masks & *(v32u8*)&in[i];
    }
    out += n_vec;
    n -= n_vec;
#endif
    for (size_t i = 0; i < n; i++) {
        out[i] ^= value_barrier_w(mask) & in[i];
    }
}
#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CURVE25519_INTERNAL_H
