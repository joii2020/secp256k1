#ifndef _INCLUDE_SECP256K1_TYPEDEF_H_
#define _INCLUDE_SECP256K1_TYPEDEF_H_

#include "include/libsecp256k1-config.h"

#include <stdint.h>

#if defined(USE_FORCE_WIDEMUL_INT128)
# define SECP256K1_WIDEMUL_INT128 1
#elif defined(USE_FORCE_WIDEMUL_INT64)
# define SECP256K1_WIDEMUL_INT64 1
#elif defined(UINT128_MAX) || defined(__SIZEOF_INT128__)
# define SECP256K1_WIDEMUL_INT128 1
#else
# define SECP256K1_WIDEMUL_INT64 1
#endif

#if defined(SECP256K1_WIDEMUL_INT128)
/*#include "field_5x52.h"*/

typedef struct {
    uint64_t n[4];
} secp256k1_fe_storage;

typedef struct {
    /* X = sum(i=0..4, n[i]*2^(i*52)) mod p
     * where p = 2^256 - 0x1000003D1
     */
    uint64_t n[5];
#ifdef VERIFY
    int magnitude;
    int normalized;
#endif
} secp256k1_fe;

#elif defined(SECP256K1_WIDEMUL_INT64)
/*#include "field_10x26.h"*/

typedef struct {
    uint32_t n[8];
} secp256k1_fe_storage;

typedef struct {
    /* X = sum(i=0..9, n[i]*2^(i*26)) mod p
     * where p = 2^256 - 0x1000003D1
     */
    uint32_t n[10];
#ifdef VERIFY
    int magnitude;
    int normalized;
#endif
} secp256k1_fe;

#else
#error "Please select wide multiplication implementation"
#endif

typedef struct {
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
} secp256k1_ge_storage;

typedef struct {
    /* For accelerating the computation of a*P + b*G: */
    secp256k1_ge_storage (*pre_g)[];    /* odd multiples of the generator */
    secp256k1_ge_storage (*pre_g_128)[]; /* odd multiples of 2^128*generator */
} secp256k1_ecmult_context;

#if defined(EXHAUSTIVE_TEST_ORDER)
/*#include "scalar_low.h"*/
typedef uint32_t secp256k1_scalar;
#elif defined(SECP256K1_WIDEMUL_INT128)
/*#include "scalar_4x64.h"*/
typedef struct {
    uint64_t d[4];
} secp256k1_scalar;
#elif defined(SECP256K1_WIDEMUL_INT64)
/*#include "scalar_8x32.h"*/
typedef struct {
    uint32_t d[8];
} secp256k1_scalar;
#else
#error "Please select wide multiplication implementation"
#endif


#if ECMULT_GEN_PREC_BITS != 2 && ECMULT_GEN_PREC_BITS != 4 && ECMULT_GEN_PREC_BITS != 8
#  error "Set ECMULT_GEN_PREC_BITS to 2, 4 or 8."
#endif
#define ECMULT_GEN_PREC_B ECMULT_GEN_PREC_BITS
#define ECMULT_GEN_PREC_G (1 << ECMULT_GEN_PREC_B)
#define ECMULT_GEN_PREC_N (256 / ECMULT_GEN_PREC_B)

/** A group element of the secp256k1 curve, in jacobian coordinates. */
typedef struct {
    secp256k1_fe x; /* actual X: x/z^2 */
    secp256k1_fe y; /* actual Y: y/z^3 */
    secp256k1_fe z;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_gej;

typedef struct {
    /* For accelerating the computation of a*G:
     * To harden against timing attacks, use the following mechanism:
     * * Break up the multiplicand into groups of PREC_B bits, called n_0, n_1, n_2, ..., n_(PREC_N-1).
     * * Compute sum(n_i * (PREC_G)^i * G + U_i, i=0 ... PREC_N-1), where:
     *   * U_i = U * 2^i, for i=0 ... PREC_N-2
     *   * U_i = U * (1-2^(PREC_N-1)), for i=PREC_N-1
     *   where U is a point with no known corresponding scalar. Note that sum(U_i, i=0 ... PREC_N-1) = 0.
     * For each i, and each of the PREC_G possible values of n_i, (n_i * (PREC_G)^i * G + U_i) is
     * precomputed (call it prec(i, n_i)). The formula now becomes sum(prec(i, n_i), i=0 ... PREC_N-1).
     * None of the resulting prec group elements have a known scalar, and neither do any of
     * the intermediate sums while computing a*G.
     */
    secp256k1_ge_storage (*prec)[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G]; /* prec[j][i] = (PREC_G)^j * i * G + U_i */
    secp256k1_scalar blind;
    secp256k1_gej initial;
} secp256k1_ecmult_gen_context;

typedef struct {
    void (*fn)(const char *text, void* data);
    const void* data;
} secp256k1_callback;

struct secp256k1_context_struct {
    secp256k1_ecmult_context ecmult_ctx;
    secp256k1_ecmult_gen_context ecmult_gen_ctx;
    secp256k1_callback illegal_callback;
    secp256k1_callback error_callback;
    int declassify;
};

#if defined(__BIGGEST_ALIGNMENT__)
#define ALIGNMENT __BIGGEST_ALIGNMENT__
#else
/* Using 16 bytes alignment because common architectures never have alignment
 * requirements above 8 for any of the types we care about. In addition we
 * leave some room because currently we don't care about a few bytes. */
#define ALIGNMENT 16
#endif

#define ROUND_TO_ALIGN(size) ((((size) + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT)

#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
#define SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE_TMP \
    ROUND_TO_ALIGN(sizeof(*((secp256k1_ecmult_gen_context*) NULL)->prec))
#else
#define SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE_TMP 0
#endif
static const size_t SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE = 
    SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE_TMP;

/** The number of entries a table with precomputed multiples needs to have. */
#define ECMULT_TABLE_SIZE(w) (1 << ((w)-2))

#if defined(EXHAUSTIVE_TEST_ORDER)
/* We need to lower these values for exhaustive tests because
 * the tables cannot have infinities in them (this breaks the
 * affine-isomorphism stuff which tracks z-ratios) */
#  if EXHAUSTIVE_TEST_ORDER > 128
#    define WINDOW_A 5
#    define WINDOW_G 8
#  elif EXHAUSTIVE_TEST_ORDER > 8
#    define WINDOW_A 4
#    define WINDOW_G 4
#  else
#    define WINDOW_A 2
#    define WINDOW_G 2
#  endif
#else
/* optimal for 128-bit and 256-bit exponents. */
#  define WINDOW_A 5
/** Larger values for ECMULT_WINDOW_SIZE result in possibly better
 *  performance at the cost of an exponentially larger precomputed
 *  table. The exact table size is
 *      (1 << (WINDOW_G - 2)) * sizeof(secp256k1_ge_storage)  bytes,
 *  where sizeof(secp256k1_ge_storage) is typically 64 bytes but can
 *  be larger due to platform-specific padding and alignment.
 *  Two tables of this size are used (due to the endomorphism
 *  optimization).
 */
#  define WINDOW_G ECMULT_WINDOW_SIZE
#endif

#define SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE_TMP \
    ROUND_TO_ALIGN(sizeof((*((secp256k1_ecmult_context*) NULL)->pre_g)[0]) * ECMULT_TABLE_SIZE(WINDOW_G)) \
    + ROUND_TO_ALIGN(sizeof((*((secp256k1_ecmult_context*) NULL)->pre_g_128)[0]) * ECMULT_TABLE_SIZE(WINDOW_G))

static const size_t SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE =
    SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE_TMP;

struct secp256k1_context_verify_struct {
    struct secp256k1_context_struct ctx;
    char tmp_verify_buffer[SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE_TMP];
};

typedef struct secp256k1_context_verify_struct secp256k1_context_verify;

#endif /* _INCLUDE_SECP256K1_TYPEDEF_H_ */
