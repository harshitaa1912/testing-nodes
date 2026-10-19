

#ifndef MLK_INDCPA_H
#define MLK_INDCPA_H

#include "cbmc.h"
#include "common.h"
#include "poly_k.h"

#define mlk_gen_matrix MLK_NAMESPACE_K(gen_matrix)

MLK_INTERNAL_API
void mlk_gen_matrix(mlk_polymat *a, const uint8_t seed[MLKEM_SYMBYTES],
                    int transposed)
__contract__(
  requires(memory_no_alias(a, sizeof(mlk_polymat)))
  requires(memory_no_alias(seed, MLKEM_SYMBYTES))
  requires(transposed == 0 || transposed == 1)
  assigns(memory_slice(a, sizeof(mlk_polymat)))
  ensures(forall(x, 0, MLKEM_K, forall(y, 0, MLKEM_K,
  array_bound(a->vec[x].vec[y].coeffs, 0, MLKEM_N, 0, MLKEM_Q))))
);

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
#define mlk_indcpa_keypair_derand \
  MLK_NAMESPACE_K(indcpa_keypair_derand) MLK_CONTEXT_PARAMETERS_3

MLK_INTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_indcpa_keypair_derand(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                              uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                              const uint8_t coins[MLKEM_SYMBYTES],
                              MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(pk, MLKEM_INDCPA_PUBLICKEYBYTES))
  requires(memory_no_alias(sk, MLKEM_INDCPA_SECRETKEYBYTES))
  requires(memory_no_alias(coins, MLKEM_SYMBYTES))
  assigns(memory_slice(pk, MLKEM_INDCPA_PUBLICKEYBYTES))
  assigns(memory_slice(sk, MLKEM_INDCPA_SECRETKEYBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_OUT_OF_MEMORY)

  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(pk, MLKEM_INDCPA_PUBLICKEYBYTES))
  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(sk, MLKEM_INDCPA_SECRETKEYBYTES))
);
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_indcpa_enc MLK_NAMESPACE_K(indcpa_enc) MLK_CONTEXT_PARAMETERS_4

MLK_INTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],
                   const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                   const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                   const uint8_t coins[MLKEM_SYMBYTES],
                   MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(c, MLKEM_INDCPA_BYTES))
  requires(memory_no_alias(m, MLKEM_INDCPA_MSGBYTES))
  requires(memory_no_alias(pk, MLKEM_INDCPA_PUBLICKEYBYTES))
  requires(memory_no_alias(coins, MLKEM_SYMBYTES))
  assigns(memory_slice(c, MLKEM_INDCPA_BYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_OUT_OF_MEMORY)

  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(c, MLKEM_INDCPA_BYTES))
);
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_indcpa_dec MLK_NAMESPACE_K(indcpa_dec) MLK_CONTEXT_PARAMETERS_3

MLK_INTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                   const uint8_t c[MLKEM_INDCPA_BYTES],
                   const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                   MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(c, MLKEM_INDCPA_BYTES))
  requires(memory_no_alias(m, MLKEM_INDCPA_MSGBYTES))
  requires(memory_no_alias(sk, MLKEM_INDCPA_SECRETKEYBYTES))
  assigns(memory_slice(m, MLKEM_INDCPA_MSGBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_OUT_OF_MEMORY)

  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(m, MLKEM_INDCPA_MSGBYTES))
);
#endif

#endif
