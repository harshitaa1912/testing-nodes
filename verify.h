

#ifndef MLK_VERIFY_H
#define MLK_VERIFY_H

#include "cbmc.h"
#include "common.h"

#if defined(MLK_HAVE_INLINE_ASM) && !defined(MLK_CONFIG_NO_ASM_VALUE_BARRIER)
#define MLK_USE_ASM_VALUE_BARRIER
#endif

#if !defined(MLK_USE_ASM_VALUE_BARRIER)

#define mlk_ct_opt_blocker_u64 MLK_NAMESPACE(ct_opt_blocker_u64)
extern volatile uint64_t mlk_ct_opt_blocker_u64;

static MLK_INLINE uint64_t mlk_ct_get_optblocker_u64(void)
__contract__(ensures(return_value == 0)) { return mlk_ct_opt_blocker_u64; }

static MLK_INLINE uint8_t mlk_ct_get_optblocker_u8(void)
__contract__(ensures(return_value == 0)) { return (uint8_t)mlk_ct_get_optblocker_u64(); }

static MLK_INLINE uint32_t mlk_ct_get_optblocker_u32(void)
__contract__(ensures(return_value == 0)) { return (uint32_t)mlk_ct_get_optblocker_u64(); }

static MLK_INLINE int32_t mlk_ct_get_optblocker_i32(void)
__contract__(ensures(return_value == 0)) { return (int32_t)mlk_ct_get_optblocker_u64(); }

static MLK_INLINE uint32_t mlk_value_barrier_u32(uint32_t b)
__contract__(ensures(return_value == b)) { return (b ^ mlk_ct_get_optblocker_u32()); }

static MLK_INLINE int32_t mlk_value_barrier_i32(int32_t b)
__contract__(ensures(return_value == b)) { return (b ^ mlk_ct_get_optblocker_i32()); }

static MLK_INLINE uint8_t mlk_value_barrier_u8(uint8_t b)
__contract__(ensures(return_value == b)) { return (b ^ mlk_ct_get_optblocker_u8()); }

#else

static MLK_INLINE uint32_t mlk_value_barrier_u32(uint32_t b)
__contract__(ensures(return_value == b))
{
  __asm__ volatile("" : "+r"(b));
  return b;
}

static MLK_INLINE int32_t mlk_value_barrier_i32(int32_t b)
__contract__(ensures(return_value == b))
{
  __asm__ volatile("" : "+r"(b));
  return b;
}

static MLK_INLINE uint8_t mlk_value_barrier_u8(uint8_t b)
__contract__(ensures(return_value == b))
{
  __asm__ volatile("" : "+r"(b));
  return b;
}

#endif

#ifdef CBMC
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#endif

static MLK_ALWAYS_INLINE int16_t mlk_cast_uint16_to_int16(uint16_t x)
{

  return (int16_t)x;
}
#ifdef CBMC
#pragma CPROVER check pop
#endif

static MLK_ALWAYS_INLINE uint16_t mlk_cast_int32_to_uint16(int32_t x)
{
  return (uint16_t)(x & (int32_t)UINT16_MAX);
}

static MLK_ALWAYS_INLINE uint16_t mlk_cast_int16_to_uint16(int32_t x)
{
  return mlk_cast_int32_to_uint16(x);
}

static MLK_INLINE uint16_t mlk_ct_cmask_neg_i16(int16_t x)
__contract__(ensures(return_value == ((x < 0) ? 0xFFFF : 0)))
{
  int32_t tmp = mlk_value_barrier_i32((int32_t)x);

  tmp >>= 16;
  return mlk_cast_int32_to_uint16(tmp);
}

static MLK_INLINE uint16_t mlk_ct_cmask_nonzero_u16(uint16_t x)
__contract__(ensures(return_value == ((x == 0) ? 0 : 0xFFFF)))
{
  int32_t tmp = mlk_value_barrier_i32(-((int32_t)x));

  tmp >>= 16;
  return mlk_cast_int32_to_uint16(tmp);
}

static MLK_INLINE uint8_t mlk_ct_cmask_nonzero_u8(uint8_t x)
__contract__(ensures(return_value == ((x == 0) ? 0 : 0xFF)))
{
  uint16_t mask = mlk_ct_cmask_nonzero_u16((uint16_t)x);
  return (uint8_t)(mask & 0xFF);
}

static MLK_INLINE int16_t mlk_ct_sel_int16(int16_t a, int16_t b, uint16_t cond)
__contract__(ensures(return_value == (cond ? a : b)))
{
  uint16_t au = mlk_cast_int16_to_uint16(a);
  uint16_t bu = mlk_cast_int16_to_uint16(b);
  uint16_t res = bu ^ (mlk_ct_cmask_nonzero_u16(cond) & (au ^ bu));
  return mlk_cast_uint16_to_int16(res);
}

static MLK_INLINE uint8_t mlk_ct_sel_uint8(uint8_t a, uint8_t b, uint8_t cond)
__contract__(ensures(return_value == (cond ? a : b)))
{
  return b ^ (mlk_ct_cmask_nonzero_u8(cond) & (a ^ b));
}

static MLK_INLINE uint8_t mlk_ct_memcmp(const uint8_t *a, const uint8_t *b,
                                        const size_t len)
__contract__(
  requires(len <= UINT16_MAX)
  requires(memory_no_alias(a, len))
  requires(memory_no_alias(b, len))
  ensures((return_value == 0) || (return_value == 0xFF))
  ensures((return_value == 0) == forall(i, 0, len, (a[i] == b[i]))))
{
  uint8_t r = 0, s = 0;
  unsigned i;

  for (i = 0; i < len; i++)
  __loop__(
    invariant(i <= len)
    invariant((r == 0) == (forall(k, 0, i, (a[k] == b[k]))))
    decreases(len - i))
  {
    r |= a[i] ^ b[i];

    s ^= a[i] ^ b[i];
  }

  return (mlk_value_barrier_u8(mlk_ct_cmask_nonzero_u8(r) ^ s) ^ s);
}

static MLK_INLINE void mlk_ct_cmov_zero(uint8_t *r, const uint8_t *x,
                                        size_t len, uint8_t b)
__contract__(
  requires(len <= UINT32_MAX)
  requires(memory_no_alias(r, len))
  requires(memory_no_alias(x, len))
  assigns(memory_slice(r, len))
  ensures(forall(i, 0, len, (r[i] == (b == 0 ? x[i] : old(r)[i])))))
{
  size_t i;
  for (i = 0; i < len; i++)
  __loop__(
    invariant(i <= len)
    invariant(forall(k, 0, i, r[k] == (b == 0 ? x[k] : loop_entry(r)[k])))
    decreases(len - i))
  {
    r[i] = mlk_ct_sel_uint8(r[i], x[i], b);
  }
}

#if !defined(MLK_CONFIG_CUSTOM_ZEROIZE)
#if defined(MLK_SYS_WINDOWS)
#include <windows.h>
#elif !defined(MLK_HAVE_INLINE_ASM)
#error No plausibly-secure implementation of mlk_zeroize available. Please provide your own using MLK_CONFIG_CUSTOM_ZEROIZE.
#endif

static MLK_INLINE void mlk_zeroize(void *ptr, size_t len)
__contract__(
  requires(len <= UINT32_MAX)
  requires(memory_no_alias(ptr, len))
  assigns(memory_slice(ptr, len))
  ensures(array_zeroized_u8((uint8_t *)ptr, len)))
{
#if defined(MLK_SYS_WINDOWS)
  SecureZeroMemory(ptr, len);
#else
  mlk_memset(ptr, 0, len);

  __asm__ volatile("" : : "r"(ptr) : "memory");
#endif
}
#endif

#endif
