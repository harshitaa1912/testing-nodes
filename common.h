

#ifndef MLK_COMMON_H
#define MLK_COMMON_H

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>
#endif

#define MLK_BUILD_INTERNAL

#if defined(MLK_CONFIG_FILE)
#include MLK_CONFIG_FILE
#else
#include "../mlkem_native_config.h"
#endif

#include "params.h"
#include "sys.h"

#if !defined(MLK_CONFIG_INTERNAL_API_QUALIFIER)
#define MLK_INTERNAL_API
#define MLK_INTERNAL_DATA_DECLARATION extern
#define MLK_INTERNAL_DATA_DEFINITION
#else
#define MLK_INTERNAL_API MLK_CONFIG_INTERNAL_API_QUALIFIER
#define MLK_INTERNAL_DATA_DECLARATION MLK_CONFIG_INTERNAL_API_QUALIFIER
#define MLK_INTERNAL_DATA_DEFINITION MLK_CONFIG_INTERNAL_API_QUALIFIER
#endif

#if !defined(MLK_CONFIG_EXTERNAL_API_QUALIFIER)
#define MLK_EXTERNAL_API
#else
#define MLK_EXTERNAL_API MLK_CONFIG_EXTERNAL_API_QUALIFIER
#endif

#define MLK_CONCAT_(x1, x2) x1##x2
#define MLK_CONCAT(x1, x2) MLK_CONCAT_(x1, x2)

#if (defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED) || \
     defined(MLK_CONFIG_MULTILEVEL_NO_SHARED))
#define MLK_ADD_PARAM_SET(s) MLK_CONCAT(s, MLK_CONFIG_PARAMETER_SET)
#else
#define MLK_ADD_PARAM_SET(s) s
#endif

#define MLK_NAMESPACE_PREFIX MLK_CONCAT(MLK_CONFIG_NAMESPACE_PREFIX, _)
#define MLK_NAMESPACE_PREFIX_K \
  MLK_CONCAT(MLK_ADD_PARAM_SET(MLK_CONFIG_NAMESPACE_PREFIX), _)

#define MLK_NAMESPACE(s) MLK_CONCAT(MLK_NAMESPACE_PREFIX, s)
#define MLK_NAMESPACE_K(s) MLK_CONCAT(MLK_NAMESPACE_PREFIX_K, s)

#if !defined(__APPLE__)
#define MLK_ASM_NAMESPACE(sym) MLK_NAMESPACE(sym)
#else
#define MLK_ASM_NAMESPACE(sym) MLK_CONCAT(_, MLK_NAMESPACE(sym))
#endif

#if defined(MLK_SYS_X86_64)
#define MLK_ASM_FN_SYMBOL(sym) MLK_ASM_NAMESPACE(sym) : MLK_CET_ENDBR
#elif defined(MLK_SYS_ARMV81M_MVE)

#define MLK_ASM_FN_SYMBOL(sym) \
  .type MLK_ASM_NAMESPACE(sym), %function; \
  MLK_ASM_NAMESPACE(sym) :

#else
#define MLK_ASM_FN_SYMBOL(sym) MLK_ASM_NAMESPACE(sym) :
#endif

#if defined(__ELF__)
#define MLK_ASM_FN_SIZE(sym) \
  .size MLK_ASM_NAMESPACE(sym), .- MLK_ASM_NAMESPACE(sym)
#else
#define MLK_ASM_FN_SIZE(sym)
#endif

#define MLK_EMPTY_CU(s) extern int MLK_NAMESPACE_K(empty_cu_##s);

#if defined(MLK_CONFIG_NO_ASM)
#undef MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
#undef MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#endif

#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH) && \
    !defined(MLK_CONFIG_ARITH_BACKEND_FILE)
#error Bad configuration: MLK_CONFIG_USE_NATIVE_BACKEND_ARITH is set, but MLK_CONFIG_ARITH_BACKEND_FILE is not.
#endif

#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202) && \
    !defined(MLK_CONFIG_FIPS202_BACKEND_FILE)
#error Bad configuration: MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202 is set, but MLK_CONFIG_FIPS202_BACKEND_FILE is not.
#endif

#if defined(MLK_CONFIG_NO_RANDOMIZED_API) && defined(MLK_CONFIG_KEYGEN_PCT)
#error Bad configuration: MLK_CONFIG_NO_RANDOMIZED_API is incompatible with MLK_CONFIG_KEYGEN_PCT as the current PCT implementation requires enc()
#endif

#if defined(MLK_CONFIG_NO_ENCAPS_API) && defined(MLK_CONFIG_KEYGEN_PCT)
#error Bad configuration: MLK_CONFIG_NO_ENCAPS_API is incompatible with MLK_CONFIG_KEYGEN_PCT as the current PCT implementation requires enc()
#endif

#if defined(MLK_CONFIG_NO_DECAPS_API) && defined(MLK_CONFIG_KEYGEN_PCT)
#error Bad configuration: MLK_CONFIG_NO_DECAPS_API is incompatible with MLK_CONFIG_KEYGEN_PCT as the current PCT implementation requires dec()
#endif

#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH)
#include MLK_CONFIG_ARITH_BACKEND_FILE

#if defined(MLK_CHECK_APIS) && !defined(__ASSEMBLER__)
#include "native/api.h"
#endif
#endif

#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202)
#include MLK_CONFIG_FIPS202_BACKEND_FILE

#if defined(MLK_CHECK_APIS) && !defined(__ASSEMBLER__)
#include "fips202/native/api.h"
#endif
#endif

#if !defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER)
#define MLK_FIPS202_HEADER_FILE "fips202/fips202.h"
#else
#define MLK_FIPS202_HEADER_FILE MLK_CONFIG_FIPS202_CUSTOM_HEADER
#endif

#if !defined(MLK_CONFIG_FIPS202X4_CUSTOM_HEADER)
#define MLK_FIPS202X4_HEADER_FILE "fips202/fips202x4.h"
#else
#define MLK_FIPS202X4_HEADER_FILE MLK_CONFIG_FIPS202X4_CUSTOM_HEADER
#endif

#if !defined(__ASSEMBLER__)
#if !defined(MLK_CONFIG_CUSTOM_MEMCPY)
#include <string.h>
#define mlk_memcpy memcpy
#endif

#if !defined(MLK_CONFIG_CUSTOM_MEMSET)
#include <string.h>
#define mlk_memset memset
#endif

#if defined(MLK_CONFIG_CUSTOM_ALLOC_FREE) != \
    (defined(MLK_CUSTOM_ALLOC) && defined(MLK_CUSTOM_FREE))
#error Bad configuration: MLK_CONFIG_CUSTOM_ALLOC_FREE must be set together with MLK_CUSTOM_ALLOC and MLK_CUSTOM_FREE
#endif

#include "context.h"

#if !defined(MLK_CONFIG_CUSTOM_ALLOC_FREE)

#define MLK_ALLOC(v, T, N, context) \
  MLK_ALIGN T mlk_alloc_##v[N];     \
  T *v = mlk_alloc_##v

#define MLK_FREE(v, T, N, context)                     \
  do                                                   \
  {                                                    \
    MLK_CONTEXT_UNUSED(context);                       \
    mlk_zeroize(mlk_alloc_##v, sizeof(mlk_alloc_##v)); \
    (v) = NULL;                                        \
  } while (0)

#else

#define MLK_APPLY(f, args) f args

#define MLK_ALLOC(v, T, N, context) \
  MLK_APPLY(MLK_CUSTOM_ALLOC, MLK_CONTEXT_PARAMETERS_3(v, T, N, context))

#define MLK_FREE(v, T, N, context)                                            \
  do                                                                          \
  {                                                                           \
    if (v != NULL)                                                            \
    {                                                                         \
      mlk_zeroize(v, sizeof(T) * (N));                                        \
      MLK_APPLY(MLK_CUSTOM_FREE, MLK_CONTEXT_PARAMETERS_3(v, T, N, context)); \
      v = NULL;                                                               \
    }                                                                         \
  } while (0)

#endif

#define MLK_ERR_FAIL (-1)

#define MLK_ERR_OUT_OF_MEMORY (-2)

#define MLK_ERR_RNG_FAIL (-3)

#define MLK_ERR_INVALID_PK (-4)

#define MLK_ERR_INVALID_SK (-5)

#define MLK_ERR_PCT_FAIL (-6)

#endif

#endif
