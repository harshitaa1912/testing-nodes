

#ifndef MLK_POLY_H
#define MLK_POLY_H

#include "cbmc.h"
#include "common.h"
#include "debug.h"
#include "verify.h"

#define MLK_INVNTT_BOUND (8 * MLKEM_Q)

#define MLK_NTT_BOUND (8 * MLKEM_Q)

typedef struct
{
  int16_t coeffs[MLKEM_N];
} MLK_ALIGN mlk_poly;

typedef struct
{
  int16_t coeffs[MLKEM_N >> 1];
} MLK_ALIGN mlk_poly_mulcache;

static MLK_ALWAYS_INLINE int16_t mlk_montgomery_reduce(int32_t a)
__contract__(
    requires(a < +(INT32_MAX - (((int32_t)1 << 15) * MLKEM_Q)) &&
             a > -(INT32_MAX - (((int32_t)1 << 15) * MLKEM_Q)))

)
{

  const uint32_t QINV = 62209;

  const uint16_t a_reduced = mlk_cast_int32_to_uint16(a);
  const uint16_t a_inverted = (a_reduced * QINV) & UINT16_MAX;

  const int16_t t = mlk_cast_uint16_to_int16(a_inverted);

  int32_t r;

  mlk_assert(a < +(INT32_MAX - (((int32_t)1 << 15) * MLKEM_Q)) &&
             a > -(INT32_MAX - (((int32_t)1 << 15) * MLKEM_Q)));

  r = a - ((int32_t)t * MLKEM_Q);

  r = r >> 16;

  return (int16_t)r;
}

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
#define mlk_poly_tomont MLK_NAMESPACE(poly_tomont)

MLK_INTERNAL_API
void mlk_poly_tomont(mlk_poly *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_Q))
);
#endif

#define mlk_poly_mulcache_compute MLK_NAMESPACE(poly_mulcache_compute)

MLK_INTERNAL_API
void mlk_poly_mulcache_compute(mlk_poly_mulcache *x, const mlk_poly *a)
__contract__(
  requires(memory_no_alias(x, sizeof(mlk_poly_mulcache)))
  requires(memory_no_alias(a, sizeof(mlk_poly)))
  assigns(memory_slice(x, sizeof(mlk_poly_mulcache)))
);

#define mlk_poly_reduce MLK_NAMESPACE(poly_reduce)

MLK_INTERNAL_API
void mlk_poly_reduce(mlk_poly *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
);

#define mlk_poly_add MLK_NAMESPACE(poly_add)

MLK_INTERNAL_API
void mlk_poly_add(mlk_poly *r, const mlk_poly *b)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  requires(memory_no_alias(b, sizeof(mlk_poly)))
  requires(forall(k0, 0, MLKEM_N, (int32_t) r->coeffs[k0] + b->coeffs[k0] <= INT16_MAX))
  requires(forall(k1, 0, MLKEM_N, (int32_t) r->coeffs[k1] + b->coeffs[k1] >= INT16_MIN))
  ensures(forall(k, 0, MLKEM_N, r->coeffs[k] == old(*r).coeffs[k] + b->coeffs[k]))
  assigns(memory_slice(r, sizeof(mlk_poly)))
);

#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_sub MLK_NAMESPACE(poly_sub)

MLK_INTERNAL_API
void mlk_poly_sub(mlk_poly *r, const mlk_poly *b)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  requires(memory_no_alias(b, sizeof(mlk_poly)))
  requires(forall(k0, 0, MLKEM_N, (int32_t) r->coeffs[k0] - b->coeffs[k0] <= INT16_MAX))
  requires(forall(k1, 0, MLKEM_N, (int32_t) r->coeffs[k1] - b->coeffs[k1] >= INT16_MIN))
  ensures(forall(k, 0, MLKEM_N, r->coeffs[k] == old(*r).coeffs[k] - b->coeffs[k]))
  assigns(memory_slice(r, sizeof(mlk_poly)))
);
#endif

#define mlk_poly_ntt MLK_NAMESPACE(poly_ntt)

MLK_INTERNAL_API
void mlk_poly_ntt(mlk_poly *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  requires(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_Q))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLK_NTT_BOUND))
);

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_invntt_tomont MLK_NAMESPACE(poly_invntt_tomont)

MLK_INTERNAL_API
void mlk_poly_invntt_tomont(mlk_poly *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLK_INVNTT_BOUND))
);
#endif

#endif
