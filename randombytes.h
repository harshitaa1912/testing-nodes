
#ifndef MLK_RANDOMBYTES_H
#define MLK_RANDOMBYTES_H

#include "cbmc.h"
#include "common.h"

#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)
#if !defined(MLK_CONFIG_CUSTOM_RANDOMBYTES)

int randombytes(uint8_t *out, size_t outlen);

MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_randombytes(uint8_t *out, size_t outlen)
__contract__(
  requires(memory_no_alias(out, outlen))
  assigns(memory_slice(out, outlen))) { return randombytes(out, outlen); }
#endif
#endif
#endif
