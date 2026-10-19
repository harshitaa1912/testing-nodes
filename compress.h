

#ifndef MLK_COMPRESS_H
#define MLK_COMPRESS_H

#include "cbmc.h"
#include "common.h"
#include "debug.h"
#include "poly.h"
#include "verify.h"

#ifdef CBMC
#pragma CPROVER check push
#pragma CPROVER check disable "unsigned-overflow"
#endif

static MLK_INLINE uint8_t mlk_scalar_compress_d1(int16_t u)
__contract__(
  requires(0 <= u && u <= MLKEM_Q - 1)
  ensures(return_value < 2)
  ensures(return_value == (((uint32_t)u * 2 + MLKEM_Q / 2) / MLKEM_Q) % 2)  )
{

  uint32_t d0 = (uint32_t)u * 1290168;

  return (uint8_t)((d0 + ((uint32_t)1u << 30)) >> 31);
}
#ifdef CBMC
#pragma CPROVER check pop
#endif

#ifdef CBMC
#pragma CPROVER check push
#pragma CPROVER check disable "unsigned-overflow"
#endif

static MLK_INLINE uint8_t mlk_scalar_compress_d4(int16_t u)
__contract__(
  requires(0 <= u && u <= MLKEM_Q - 1)
  ensures(return_value < 16)
  ensures(return_value == (((uint32_t)u * 16 + MLKEM_Q / 2) / MLKEM_Q) % 16))
{

  uint32_t d0 = (uint32_t)u * 1290160;

  return (uint8_t)((d0 + ((uint32_t)1u << 27)) >> 28);
}
#ifdef CBMC
#pragma CPROVER check pop
#endif

static MLK_INLINE int16_t mlk_scalar_decompress_d4(uint8_t u)
__contract__(
  requires(0 <= u && u < 16)
  ensures(return_value <= (MLKEM_Q - 1))
)
{

  return (int16_t)((((uint32_t)u * MLKEM_Q) + 8) >> 4);
}

#ifdef CBMC
#pragma CPROVER check push
#pragma CPROVER check disable "unsigned-overflow"
#endif

static MLK_INLINE uint8_t mlk_scalar_compress_d5(int16_t u)
__contract__(
  requires(0 <= u && u <= MLKEM_Q - 1)
  ensures(return_value < 32)
  ensures(return_value == (((uint32_t)u * 32 + MLKEM_Q / 2) / MLKEM_Q) % 32)  )
{

  uint32_t d0 = (uint32_t)u * 1290176;

  return (uint8_t)((d0 + ((uint32_t)1u << 26)) >> 27);
}
#ifdef CBMC
#pragma CPROVER check pop
#endif

static MLK_INLINE int16_t mlk_scalar_decompress_d5(uint8_t u)
__contract__(
  requires(0 <= u && u < 32)
  ensures(0 <= return_value && return_value <= MLKEM_Q - 1)
)
{

  return (int16_t)((((uint32_t)u * MLKEM_Q) + 16) >> 5);
}

#ifdef CBMC
#pragma CPROVER check push
#pragma CPROVER check disable "unsigned-overflow"
#endif

static MLK_INLINE uint16_t mlk_scalar_compress_d10(int16_t u)
__contract__(
  requires(0 <= u && u <= MLKEM_Q - 1)
  ensures(return_value < (1u << 10))
  ensures(return_value == (((uint32_t)u * (1u << 10) + MLKEM_Q / 2) / MLKEM_Q) % (1 << 10)))
{

  uint64_t d0 = (uint64_t)u * 2642263040;
  d0 = (d0 + ((uint64_t)1u << 32)) >> 33;
  return (d0 & 0x3FF);
}
#ifdef CBMC
#pragma CPROVER check pop
#endif

static MLK_INLINE int16_t mlk_scalar_decompress_d10(uint16_t u)
__contract__(
  requires(0 <= u && u < 1024)
  ensures(0 <= return_value && return_value <= (MLKEM_Q - 1))
)
{

  return (int16_t)((((uint32_t)u * MLKEM_Q) + 512) >> 10);
}

#ifdef CBMC
#pragma CPROVER check push
#pragma CPROVER check disable "unsigned-overflow"
#endif

static MLK_INLINE uint16_t mlk_scalar_compress_d11(int16_t u)
__contract__(
  requires(0 <= u && u <= MLKEM_Q - 1)
  ensures(return_value < (1u << 11))
  ensures(return_value == (((uint32_t)u * (1u << 11) + MLKEM_Q / 2) / MLKEM_Q) % (1 << 11)))
{

  uint64_t d0 = (uint64_t)u * 5284526080;
  d0 = (d0 + ((uint64_t)1u << 32)) >> 33;
  return (d0 & 0x7FF);
}
#ifdef CBMC
#pragma CPROVER check pop
#endif

static MLK_INLINE int16_t mlk_scalar_decompress_d11(uint16_t u)
__contract__(
  requires(0 <= u && u < 2048)
  ensures(0 <= return_value && return_value <= (MLKEM_Q - 1))
)
{

  return (int16_t)((((uint32_t)u * MLKEM_Q) + 1024) >> 11);
}

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#if defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED) || (MLKEM_K == 2 || MLKEM_K == 3)
#define mlk_poly_compress_d4 MLK_NAMESPACE(poly_compress_d4)

MLK_INTERNAL_API
void mlk_poly_compress_d4(uint8_t r[MLKEM_POLYCOMPRESSEDBYTES_D4],
                          const mlk_poly *a);

#define mlk_poly_compress_d10 MLK_NAMESPACE(poly_compress_d10)

MLK_INTERNAL_API
void mlk_poly_compress_d10(uint8_t r[MLKEM_POLYCOMPRESSEDBYTES_D10],
                           const mlk_poly *a);

#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_decompress_d4 MLK_NAMESPACE(poly_decompress_d4)

MLK_INTERNAL_API
void mlk_poly_decompress_d4(mlk_poly *r,
                            const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES_D4]);

#define mlk_poly_decompress_d10 MLK_NAMESPACE(poly_decompress_d10)

MLK_INTERNAL_API
void mlk_poly_decompress_d10(mlk_poly *r,
                             const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES_D10]);
#endif
#endif

#if defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED) || MLKEM_K == 4
#define mlk_poly_compress_d5 MLK_NAMESPACE(poly_compress_d5)

MLK_INTERNAL_API
void mlk_poly_compress_d5(uint8_t r[MLKEM_POLYCOMPRESSEDBYTES_D5],
                          const mlk_poly *a);

#define mlk_poly_compress_d11 MLK_NAMESPACE(poly_compress_d11)

MLK_INTERNAL_API
void mlk_poly_compress_d11(uint8_t r[MLKEM_POLYCOMPRESSEDBYTES_D11],
                           const mlk_poly *a);

#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_decompress_d5 MLK_NAMESPACE(poly_decompress_d5)

MLK_INTERNAL_API
void mlk_poly_decompress_d5(mlk_poly *r,
                            const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES_D5]);

#define mlk_poly_decompress_d11 MLK_NAMESPACE(poly_decompress_d11)

MLK_INTERNAL_API
void mlk_poly_decompress_d11(mlk_poly *r,
                             const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES_D11]);
#endif
#endif
#endif

#if !defined(MLK_CONFIG_NO_KEYPAIR_API) || !defined(MLK_CONFIG_NO_ENCAPS_API)
#define mlk_poly_tobytes MLK_NAMESPACE(poly_tobytes)

MLK_INTERNAL_API
void mlk_poly_tobytes(uint8_t r[MLKEM_POLYBYTES], const mlk_poly *a)
__contract__(
  requires(memory_no_alias(r, MLKEM_POLYBYTES))
  requires(memory_no_alias(a, sizeof(mlk_poly)))
  requires(array_bound(a->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
  assigns(memory_slice(r, MLKEM_POLYBYTES))
);
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_frombytes MLK_NAMESPACE(poly_frombytes)

MLK_INTERNAL_API
void mlk_poly_frombytes(mlk_poly *r, const uint8_t a[MLKEM_POLYBYTES])
__contract__(
  requires(memory_no_alias(a, MLKEM_POLYBYTES))
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_UINT12_LIMIT))
);
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_frommsg MLK_NAMESPACE(poly_frommsg)

MLK_INTERNAL_API
void mlk_poly_frommsg(mlk_poly *r, const uint8_t msg[MLKEM_INDCPA_MSGBYTES])
__contract__(
  requires(memory_no_alias(msg, MLKEM_INDCPA_MSGBYTES))
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
);
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_tomsg MLK_NAMESPACE(poly_tomsg)

MLK_INTERNAL_API
void mlk_poly_tomsg(uint8_t msg[MLKEM_INDCPA_MSGBYTES], const mlk_poly *r)
__contract__(
  requires(memory_no_alias(msg, MLKEM_INDCPA_MSGBYTES))
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  requires(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
  assigns(memory_slice(msg, MLKEM_INDCPA_MSGBYTES))
);
#endif

#endif
