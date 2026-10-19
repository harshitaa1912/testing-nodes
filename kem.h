

#ifndef MLK_KEM_H
#define MLK_KEM_H

#include "cbmc.h"
#include "common.h"
#include "sys.h"

#if defined(MLK_CHECK_APIS)

#include "mlkem_native.h"

#if MLKEM_INDCCA_SECRETKEYBYTES != \
    MLKEM_SECRETKEYBYTES(MLK_CONFIG_PARAMETER_SET)
#error Mismatch for SECRETKEYBYTES between kem.h and mlkem_native.h
#endif

#if MLKEM_INDCCA_PUBLICKEYBYTES != \
    MLKEM_PUBLICKEYBYTES(MLK_CONFIG_PARAMETER_SET)
#error Mismatch for PUBLICKEYBYTES between kem.h and mlkem_native.h
#endif

#if MLKEM_INDCCA_CIPHERTEXTBYTES != \
    MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_PARAMETER_SET)
#error Mismatch for CIPHERTEXTBYTES between kem.h and mlkem_native.h
#endif

#endif

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
#define mlk_kem_keypair_derand \
  MLK_NAMESPACE_K(keypair_derand) MLK_CONTEXT_PARAMETERS_3
#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)
#define mlk_kem_keypair MLK_NAMESPACE_K(keypair) MLK_CONTEXT_PARAMETERS_2
#endif
#endif
#if !defined(MLK_CONFIG_NO_ENCAPS_API)
#define mlk_kem_enc_derand MLK_NAMESPACE_K(enc_derand) MLK_CONTEXT_PARAMETERS_4
#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)
#define mlk_kem_enc MLK_NAMESPACE_K(enc) MLK_CONTEXT_PARAMETERS_3
#endif
#define mlk_kem_check_pk MLK_NAMESPACE_K(check_pk) MLK_CONTEXT_PARAMETERS_1
#endif
#if !defined(MLK_CONFIG_NO_DECAPS_API)
#define mlk_kem_dec MLK_NAMESPACE_K(dec) MLK_CONTEXT_PARAMETERS_3
#define mlk_kem_check_sk MLK_NAMESPACE_K(check_sk) MLK_CONTEXT_PARAMETERS_1
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_check_pk(const uint8_t pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_INVALID_PK ||
          return_value == MLK_ERR_OUT_OF_MEMORY)
);
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_check_sk(const uint8_t sk[MLKEM_INDCCA_SECRETKEYBYTES],
                     MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(sk, MLKEM_INDCCA_SECRETKEYBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_INVALID_SK ||
          return_value == MLK_ERR_OUT_OF_MEMORY)
);
#endif

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)

MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_keypair_derand(uint8_t pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                           uint8_t sk[MLKEM_INDCCA_SECRETKEYBYTES],
                           const uint8_t coins[2 * MLKEM_SYMBYTES],
                           MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  requires(memory_no_alias(sk, MLKEM_INDCCA_SECRETKEYBYTES))
  requires(memory_no_alias(coins, 2 * MLKEM_SYMBYTES))
  assigns(memory_slice(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  assigns(memory_slice(sk, MLKEM_INDCCA_SECRETKEYBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_PCT_FAIL ||
          return_value == MLK_ERR_OUT_OF_MEMORY ||
          return_value == MLK_ERR_RNG_FAIL)

  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(sk, MLKEM_INDCCA_SECRETKEYBYTES))
);

#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)

MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_keypair(uint8_t pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                    uint8_t sk[MLKEM_INDCCA_SECRETKEYBYTES],
                    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  requires(memory_no_alias(sk, MLKEM_INDCCA_SECRETKEYBYTES))
  assigns(memory_slice(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  assigns(memory_slice(sk, MLKEM_INDCCA_SECRETKEYBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_PCT_FAIL ||
          return_value == MLK_ERR_OUT_OF_MEMORY ||
          return_value == MLK_ERR_RNG_FAIL)

  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(sk, MLKEM_INDCCA_SECRETKEYBYTES))
);
#endif
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_enc_derand(uint8_t ct[MLKEM_INDCCA_CIPHERTEXTBYTES],
                       uint8_t ss[MLKEM_SSBYTES],
                       const uint8_t pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                       const uint8_t coins[MLKEM_SYMBYTES],
                       MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(ct, MLKEM_INDCCA_CIPHERTEXTBYTES))
  requires(memory_no_alias(ss, MLKEM_SSBYTES))
  requires(memory_no_alias(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  requires(memory_no_alias(coins, MLKEM_SYMBYTES))
  assigns(memory_slice(ct, MLKEM_INDCCA_CIPHERTEXTBYTES))
  assigns(memory_slice(ss, MLKEM_SSBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_INVALID_PK ||
          return_value == MLK_ERR_OUT_OF_MEMORY)

  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(ct, MLKEM_INDCCA_CIPHERTEXTBYTES))
  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(ss, MLKEM_SSBYTES))
);

#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)

MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_enc(uint8_t ct[MLKEM_INDCCA_CIPHERTEXTBYTES],
                uint8_t ss[MLKEM_SSBYTES],
                const uint8_t pk[MLKEM_INDCCA_PUBLICKEYBYTES],
                MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(ct, MLKEM_INDCCA_CIPHERTEXTBYTES))
  requires(memory_no_alias(ss, MLKEM_SSBYTES))
  requires(memory_no_alias(pk, MLKEM_INDCCA_PUBLICKEYBYTES))
  assigns(memory_slice(ct, MLKEM_INDCCA_CIPHERTEXTBYTES))
  assigns(memory_slice(ss, MLKEM_SSBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_INVALID_PK ||
          return_value == MLK_ERR_OUT_OF_MEMORY ||
          return_value == MLK_ERR_RNG_FAIL)

  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(ct, MLKEM_INDCCA_CIPHERTEXTBYTES))
  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(ss, MLKEM_SSBYTES))
);
#endif
#endif

#if !defined(MLK_CONFIG_NO_DECAPS_API)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_dec(uint8_t ss[MLKEM_SSBYTES],
                const uint8_t ct[MLKEM_INDCCA_CIPHERTEXTBYTES],
                const uint8_t sk[MLKEM_INDCCA_SECRETKEYBYTES],
                MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(ss, MLKEM_SSBYTES))
  requires(memory_no_alias(ct, MLKEM_INDCCA_CIPHERTEXTBYTES))
  requires(memory_no_alias(sk, MLKEM_INDCCA_SECRETKEYBYTES))
  assigns(memory_slice(ss, MLKEM_SSBYTES))
  ensures(return_value == 0 || return_value == MLK_ERR_INVALID_SK ||
          return_value == MLK_ERR_OUT_OF_MEMORY)

  ensures(return_value != 0 ==>
          array_unchanged_or_zeroized_u8(ss, MLKEM_SSBYTES))
);
#endif

#endif
