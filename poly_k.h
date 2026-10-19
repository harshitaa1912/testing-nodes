

#ifndef MLK_POLY_K_H
#define MLK_POLY_K_H

#include "common.h"
#include "compress.h"
#include "poly.h"

#define mlk_polyvec MLK_ADD_PARAM_SET(mlk_polyvec)
#define mlk_polymat MLK_ADD_PARAM_SET(mlk_polymat)
#define mlk_polyvec_mulcache MLK_ADD_PARAM_SET(mlk_polyvec_mulcache)

typedef struct
{
  mlk_poly vec[MLKEM_K];
} MLK_ALIGN mlk_polyvec;

typedef struct
{
  mlk_polyvec vec[MLKEM_K];
} MLK_ALIGN mlk_polymat;

typedef struct
{
  mlk_poly_mulcache vec[MLKEM_K];
} MLK_ALIGN mlk_polyvec_mulcache;

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_compress_du MLK_NAMESPACE_K(poly_compress_du)

static MLK_INLINE void mlk_poly_compress_du(
    uint8_t r[MLKEM_POLYCOMPRESSEDBYTES_DU], const mlk_poly *a)
__contract__(
  requires(memory_no_alias(r, MLKEM_POLYCOMPRESSEDBYTES_DU))
  requires(memory_no_alias(a, sizeof(mlk_poly)))
  requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
  assigns(memory_slice(r, MLKEM_POLYCOMPRESSEDBYTES_DU)))
{
#if MLKEM_DU == 10
  mlk_poly_compress_d10(r, a);
#elif MLKEM_DU == 11
  mlk_poly_compress_d11(r, a);
#else
#error "Invalid value of MLKEM_DU"
#endif
}
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_decompress_du MLK_NAMESPACE_K(poly_decompress_du)

static MLK_INLINE void mlk_poly_decompress_du(
    mlk_poly *r, const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES_DU])
__contract__(
  requires(memory_no_alias(a, MLKEM_POLYCOMPRESSEDBYTES_DU))
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q)))
{
#if MLKEM_DU == 10
  mlk_poly_decompress_d10(r, a);
#elif MLKEM_DU == 11
  mlk_poly_decompress_d11(r, a);
#else
#error "Invalid value of MLKEM_DU"
#endif
}
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_compress_dv MLK_NAMESPACE_K(poly_compress_dv)

static MLK_INLINE void mlk_poly_compress_dv(
    uint8_t r[MLKEM_POLYCOMPRESSEDBYTES_DV], const mlk_poly *a)
__contract__(
  requires(memory_no_alias(r, MLKEM_POLYCOMPRESSEDBYTES_DV))
  requires(memory_no_alias(a, sizeof(mlk_poly)))
  requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
  assigns(memory_slice(r, MLKEM_POLYCOMPRESSEDBYTES_DV)))
{
#if MLKEM_DV == 4
  mlk_poly_compress_d4(r, a);
#elif MLKEM_DV == 5
  mlk_poly_compress_d5(r, a);
#else
#error "Invalid value of MLKEM_DV"
#endif
}
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_decompress_dv MLK_NAMESPACE_K(poly_decompress_dv)

static MLK_INLINE void mlk_poly_decompress_dv(
    mlk_poly *r, const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES_DV])
__contract__(
  requires(memory_no_alias(a, MLKEM_POLYCOMPRESSEDBYTES_DV))
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q)))
{
#if MLKEM_DV == 4
  mlk_poly_decompress_d4(r, a);
#elif MLKEM_DV == 5
  mlk_poly_decompress_d5(r, a);
#else
#error "Invalid value of MLKEM_DV"
#endif
}
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_polyvec_compress_du MLK_NAMESPACE_K(polyvec_compress_du)

MLK_INTERNAL_API
void mlk_polyvec_compress_du(uint8_t r[MLKEM_POLYVECCOMPRESSEDBYTES_DU],
                             const mlk_polyvec *a)
__contract__(
  requires(memory_no_alias(r, MLKEM_POLYVECCOMPRESSEDBYTES_DU))
  requires(memory_no_alias(a, sizeof(mlk_polyvec)))
  requires(forall(k0, 0, MLKEM_K,
         array_bound(a->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_Q)))
  assigns(memory_slice(r, MLKEM_POLYVECCOMPRESSEDBYTES_DU))
);
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_polyvec_decompress_du MLK_NAMESPACE_K(polyvec_decompress_du)

MLK_INTERNAL_API
void mlk_polyvec_decompress_du(mlk_polyvec *r,
                               const uint8_t a[MLKEM_POLYVECCOMPRESSEDBYTES_DU])
__contract__(
  requires(memory_no_alias(a, MLKEM_POLYVECCOMPRESSEDBYTES_DU))
  requires(memory_no_alias(r, sizeof(mlk_polyvec)))
  assigns(memory_slice(r, sizeof(mlk_polyvec)))
  ensures(forall(k0, 0, MLKEM_K,
         array_bound(r->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_Q)))
);
#endif

#if !defined(MLK_CONFIG_NO_KEYPAIR_API) || !defined(MLK_CONFIG_NO_ENCAPS_API)
#define mlk_polyvec_tobytes MLK_NAMESPACE_K(polyvec_tobytes)

MLK_INTERNAL_API
void mlk_polyvec_tobytes(uint8_t r[MLKEM_POLYVECBYTES], const mlk_polyvec *a)
__contract__(
  requires(memory_no_alias(a, sizeof(mlk_polyvec)))
  requires(memory_no_alias(r, MLKEM_POLYVECBYTES))
  requires(forall(k0, 0, MLKEM_K,
         array_bound(a->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_Q)))
  assigns(memory_slice(r, MLKEM_POLYVECBYTES))
);
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_polyvec_frombytes MLK_NAMESPACE_K(polyvec_frombytes)

MLK_INTERNAL_API
void mlk_polyvec_frombytes(mlk_polyvec *r, const uint8_t a[MLKEM_POLYVECBYTES])
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_polyvec)))
  requires(memory_no_alias(a, MLKEM_POLYVECBYTES))
  assigns(memory_slice(r, sizeof(mlk_polyvec)))
  ensures(forall(k0, 0, MLKEM_K,
        array_bound(r->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_UINT12_LIMIT)))
);
#endif

#define mlk_polyvec_ntt MLK_NAMESPACE_K(polyvec_ntt)

MLK_INTERNAL_API
void mlk_polyvec_ntt(mlk_polyvec *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_polyvec)))
  requires(forall(j, 0, MLKEM_K,
  array_abs_bound(r->vec[j].coeffs, 0, MLKEM_N, MLKEM_Q)))
  assigns(memory_slice(r, sizeof(mlk_polyvec)))
  ensures(forall(j, 0, MLKEM_K,
  array_abs_bound(r->vec[j].coeffs, 0, MLKEM_N, MLK_NTT_BOUND)))
);

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_polyvec_invntt_tomont MLK_NAMESPACE_K(polyvec_invntt_tomont)

MLK_INTERNAL_API
void mlk_polyvec_invntt_tomont(mlk_polyvec *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_polyvec)))
  assigns(memory_slice(r, sizeof(mlk_polyvec)))
  ensures(forall(j, 0, MLKEM_K,
  array_abs_bound(r->vec[j].coeffs, 0, MLKEM_N, MLK_INVNTT_BOUND)))
);
#endif

#define mlk_polyvec_basemul_acc_montgomery_cached \
  MLK_NAMESPACE_K(polyvec_basemul_acc_montgomery_cached)

MLK_INTERNAL_API
void mlk_polyvec_basemul_acc_montgomery_cached(
    mlk_poly *r, const mlk_polyvec *a, const mlk_polyvec *b,
    const mlk_polyvec_mulcache *b_cache)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  requires(memory_no_alias(a, sizeof(mlk_polyvec)))
  requires(memory_no_alias(b, sizeof(mlk_polyvec)))
  requires(memory_no_alias(b_cache, sizeof(mlk_polyvec_mulcache)))
  requires(forall(k1, 0, MLKEM_K,
     array_bound(a->vec[k1].coeffs, 0, MLKEM_N, 0, MLKEM_UINT12_LIMIT)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
);

#define mlk_polyvec_mulcache_compute MLK_NAMESPACE_K(polyvec_mulcache_compute)

MLK_INTERNAL_API
void mlk_polyvec_mulcache_compute(mlk_polyvec_mulcache *x, const mlk_polyvec *a)
__contract__(
  requires(memory_no_alias(x, sizeof(mlk_polyvec_mulcache)))
  requires(memory_no_alias(a, sizeof(mlk_polyvec)))
  assigns(memory_slice(x, sizeof(mlk_polyvec_mulcache)))
);

#define mlk_polyvec_reduce MLK_NAMESPACE_K(polyvec_reduce)

MLK_INTERNAL_API
void mlk_polyvec_reduce(mlk_polyvec *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_polyvec)))
  assigns(memory_slice(r, sizeof(mlk_polyvec)))
  ensures(forall(k0, 0, MLKEM_K,
    array_bound(r->vec[k0].coeffs, 0, MLKEM_N, 0, MLKEM_Q)))
);

#define mlk_polyvec_add MLK_NAMESPACE_K(polyvec_add)

MLK_INTERNAL_API
void mlk_polyvec_add(mlk_polyvec *r, const mlk_polyvec *b)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_polyvec)))
  requires(memory_no_alias(b, sizeof(mlk_polyvec)))
  requires(forall(j0, 0, MLKEM_K,
          forall(k0, 0, MLKEM_N,
            (int32_t)r->vec[j0].coeffs[k0] + b->vec[j0].coeffs[k0] <= INT16_MAX)))
  requires(forall(j1, 0, MLKEM_K,
          forall(k1, 0, MLKEM_N,
            (int32_t)r->vec[j1].coeffs[k1] + b->vec[j1].coeffs[k1] >= INT16_MIN)))
  assigns(memory_slice(r, sizeof(mlk_polyvec)))
);

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
#define mlk_polyvec_tomont MLK_NAMESPACE_K(polyvec_tomont)

MLK_INTERNAL_API
void mlk_polyvec_tomont(mlk_polyvec *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_polyvec)))
  assigns(memory_slice(r, sizeof(mlk_polyvec)))
  ensures(forall(j, 0, MLKEM_K,
    array_abs_bound(r->vec[j].coeffs, 0, MLKEM_N, MLKEM_Q)))
);
#endif

#if !defined(MLK_CONFIG_NO_KEYPAIR_API) ||                              \
    (MLKEM_ETA1 == MLKEM_ETA2 && (!defined(MLK_CONFIG_NO_ENCAPS_API) || \
                                  !defined(MLK_CONFIG_NO_DECAPS_API)))
#define mlk_poly_getnoise_eta1_4x MLK_NAMESPACE_K(poly_getnoise_eta1_4x)

MLK_INTERNAL_API
void mlk_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const uint8_t seed[MLKEM_SYMBYTES],
                               uint8_t nonce0, uint8_t nonce1, uint8_t nonce2,
                               uint8_t nonce3)
__contract__(
  requires(memory_no_alias(seed, MLKEM_SYMBYTES))
  requires(memory_no_alias(r0, sizeof(mlk_poly)))
  requires(memory_no_alias(r1, sizeof(mlk_poly)))
  requires(memory_no_alias(r2, sizeof(mlk_poly)))
  requires(r3 == NULL || memory_no_alias(r3, sizeof(mlk_poly)))
  assigns(memory_slice(r0, sizeof(mlk_poly)))
  assigns(memory_slice(r1, sizeof(mlk_poly)))
  assigns(memory_slice(r2, sizeof(mlk_poly)))
  assigns(r3 != NULL: memory_slice(r3, sizeof(mlk_poly)))
  ensures(array_abs_bound(r0->coeffs,0, MLKEM_N, MLKEM_ETA1 + 1))
  ensures(array_abs_bound(r1->coeffs,0, MLKEM_N, MLKEM_ETA1 + 1))
  ensures(array_abs_bound(r2->coeffs,0, MLKEM_N, MLKEM_ETA1 + 1))
  ensures(r3 != NULL ==> array_abs_bound(r3->coeffs,0, MLKEM_N, MLKEM_ETA1 + 1))
);

#if MLKEM_ETA1 == MLKEM_ETA2

#define mlk_poly_getnoise_eta2_4x mlk_poly_getnoise_eta1_4x
#endif
#endif

#if (MLKEM_K == 2 || MLKEM_K == 4) && \
    (!defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API))
#define mlk_poly_getnoise_eta2 MLK_NAMESPACE_K(poly_getnoise_eta2)

MLK_INTERNAL_API
void mlk_poly_getnoise_eta2(mlk_poly *r, const uint8_t seed[MLKEM_SYMBYTES],
                            uint8_t nonce)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  requires(memory_no_alias(seed, MLKEM_SYMBYTES))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_ETA2 + 1))
);
#endif

#if MLKEM_K == 2 && \
    (!defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API))
#define mlk_poly_getnoise_eta1122_4x MLK_NAMESPACE_K(poly_getnoise_eta1122_4x)

MLK_INTERNAL_API
void mlk_poly_getnoise_eta1122_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                                  mlk_poly *r3,
                                  const uint8_t seed[MLKEM_SYMBYTES],
                                  uint8_t nonce0, uint8_t nonce1,
                                  uint8_t nonce2, uint8_t nonce3)
__contract__(
  requires(memory_no_alias(r0, sizeof(mlk_poly)))
  requires(memory_no_alias(r1, sizeof(mlk_poly)))
  requires(memory_no_alias(r2, sizeof(mlk_poly)))
  requires(memory_no_alias(r3, sizeof(mlk_poly)))
  requires(memory_no_alias(seed, MLKEM_SYMBYTES))
  assigns(memory_slice(r0, sizeof(mlk_poly)))
  assigns(memory_slice(r1, sizeof(mlk_poly)))
  assigns(memory_slice(r2, sizeof(mlk_poly)))
  assigns(memory_slice(r3, sizeof(mlk_poly)))
  ensures(array_abs_bound(r0->coeffs,0, MLKEM_N, MLKEM_ETA1 + 1)
       && array_abs_bound(r1->coeffs,0, MLKEM_N, MLKEM_ETA1 + 1)
       && array_abs_bound(r2->coeffs,0, MLKEM_N, MLKEM_ETA2 + 1)
       && array_abs_bound(r3->coeffs,0, MLKEM_N, MLKEM_ETA2 + 1))
);
#endif

#endif
