

#ifndef MLK_SAMPLING_H
#define MLK_SAMPLING_H

#include "cbmc.h"
#include "common.h"
#include "poly.h"

#if defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED) || MLKEM_ETA1 == 2 || \
    !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_poly_cbd2 MLK_NAMESPACE(poly_cbd2)

MLK_INTERNAL_API
void mlk_poly_cbd2(mlk_poly *r, const uint8_t buf[2 * MLKEM_N / 4]);
#endif

#if defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED) || MLKEM_ETA1 == 3
#define mlk_poly_cbd3 MLK_NAMESPACE(poly_cbd3)

MLK_INTERNAL_API
void mlk_poly_cbd3(mlk_poly *r, const uint8_t buf[3 * MLKEM_N / 4]);
#endif

#if !defined(MLK_CONFIG_SERIAL_FIPS202_ONLY)
#define mlk_poly_rej_uniform_x4 MLK_NAMESPACE(poly_rej_uniform_x4)

MLK_INTERNAL_API
void mlk_poly_rej_uniform_x4(mlk_poly *vec0, mlk_poly *vec1, mlk_poly *vec2,
                             mlk_poly *vec3,
                             uint8_t seed[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)])
__contract__(
  requires(memory_no_alias(vec0, sizeof(mlk_poly)))
  requires(memory_no_alias(vec1, sizeof(mlk_poly)))
  requires(memory_no_alias(vec2, sizeof(mlk_poly)))
  requires(memory_no_alias(vec3, sizeof(mlk_poly)))
  requires(memory_no_alias(seed, 4 * MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)))
  assigns(memory_slice(vec0, sizeof(mlk_poly)))
  assigns(memory_slice(vec1, sizeof(mlk_poly)))
  assigns(memory_slice(vec2, sizeof(mlk_poly)))
  assigns(memory_slice(vec3, sizeof(mlk_poly)))
  ensures(array_bound(vec0->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
  ensures(array_bound(vec1->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
  ensures(array_bound(vec2->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
  ensures(array_bound(vec3->coeffs, 0, MLKEM_N, 0, MLKEM_Q)));
#endif

#define mlk_poly_rej_uniform MLK_NAMESPACE(poly_rej_uniform)

MLK_INTERNAL_API
void mlk_poly_rej_uniform(mlk_poly *entry, uint8_t seed[MLKEM_SYMBYTES + 2])
__contract__(
  requires(memory_no_alias(entry, sizeof(mlk_poly)))
  requires(memory_no_alias(seed, MLKEM_SYMBYTES + 2))
  assigns(memory_slice(entry, sizeof(mlk_poly)))
  ensures(array_bound(entry->coeffs, 0, MLKEM_N, 0, MLKEM_Q)));

#endif
