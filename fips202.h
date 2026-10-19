
#ifndef MLK_FIPS202_FIPS202_H
#define MLK_FIPS202_FIPS202_H

#include "../cbmc.h"
#include "../common.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_384_RATE 104
#define SHA3_512_RATE 72

typedef struct
{
  uint64_t ctx[25];
} MLK_ALIGN mlk_shake128ctx;

#define mlk_shake128_absorb_once MLK_NAMESPACE(shake128_absorb_once)

void mlk_shake128_absorb_once(mlk_shake128ctx *state, const uint8_t *input,
                              size_t inlen)
__contract__(
  requires(inlen <= MLK_MAX_BUFFER_SIZE)
  requires(memory_no_alias(state, sizeof(mlk_shake128ctx)))
  requires(memory_no_alias(input, inlen))
  assigns(memory_slice(state, sizeof(mlk_shake128ctx)))
);

#define mlk_shake128_squeezeblocks MLK_NAMESPACE(shake128_squeezeblocks)

void mlk_shake128_squeezeblocks(uint8_t *output, size_t nblocks,
                                mlk_shake128ctx *state)
__contract__(
  requires(nblocks <= 8  )
  requires(memory_no_alias(state, sizeof(mlk_shake128ctx)))
  requires(memory_no_alias(output, nblocks * SHAKE128_RATE))
  assigns(memory_slice(output, nblocks * SHAKE128_RATE), memory_slice(state, sizeof(mlk_shake128ctx)))
);

#define mlk_shake128_init MLK_NAMESPACE(shake128_init)
void mlk_shake128_init(mlk_shake128ctx *state);

#define mlk_shake128_release MLK_NAMESPACE(shake128_release)
void mlk_shake128_release(mlk_shake128ctx *state);

#define mlk_shake256 MLK_NAMESPACE(shake256)

void mlk_shake256(uint8_t *output, size_t outlen, const uint8_t *input,
                  size_t inlen)
__contract__(
  requires(inlen <= MLK_MAX_BUFFER_SIZE)
  requires(outlen <= MLK_MAX_BUFFER_SIZE)
  requires(memory_no_alias(input, inlen))
  requires(memory_no_alias(output, outlen))
  assigns(memory_slice(output, outlen))
);

#define SHA3_256_HASHBYTES 32
#define mlk_sha3_256 MLK_NAMESPACE(sha3_256)

void mlk_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen)
__contract__(
  requires(inlen <= MLK_MAX_BUFFER_SIZE)
  requires(memory_no_alias(input, inlen))
  requires(memory_no_alias(output, SHA3_256_HASHBYTES))
  assigns(memory_slice(output, SHA3_256_HASHBYTES))
);

#define SHA3_512_HASHBYTES 64
#define mlk_sha3_512 MLK_NAMESPACE(sha3_512)

void mlk_sha3_512(uint8_t *output, const uint8_t *input, size_t inlen)
__contract__(
  requires(inlen <= MLK_MAX_BUFFER_SIZE)
  requires(memory_no_alias(input, inlen))
  requires(memory_no_alias(output, SHA3_512_HASHBYTES))
  assigns(memory_slice(output, SHA3_512_HASHBYTES))
);

#if !defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202) || \
    !defined(MLK_USE_NATIVE_FIPS202_X4)

#define FIPS202_X4_DEFAULT_IMPLEMENTATION
#endif

#endif
