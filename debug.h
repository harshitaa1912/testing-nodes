
#ifndef MLK_DEBUG_H
#define MLK_DEBUG_H
#include "common.h"

#if defined(MLKEM_DEBUG)

#define mlk_debug_check_assert MLK_NAMESPACE(mlkem_debug_assert)
void mlk_debug_check_assert(const char *file, int line, const int val);

#define mlk_debug_check_bounds MLK_NAMESPACE(mlkem_debug_check_bounds)
void mlk_debug_check_bounds(const char *file, int line, const int16_t *ptr,
                            unsigned len, int lower_bound_exclusive,
                            int upper_bound_exclusive);

#define mlk_assert(val) mlk_debug_check_assert(__FILE__, __LINE__, (val))

#define mlk_assert_bound(ptr, len, value_lb, value_ub)                      \
  mlk_debug_check_bounds(__FILE__, __LINE__, (const int16_t *)(ptr), (len), \
                         (value_lb) - 1, (value_ub))

#define mlk_assert_abs_bound(ptr, len, value_abs_bd) \
  mlk_assert_bound((ptr), (len), (-(value_abs_bd) + 1), (value_abs_bd))

#define mlk_assert_bound_2d(ptr, len0, len1, value_lb, value_ub) \
  mlk_assert_bound((ptr), ((len0) * (len1)), (value_lb), (value_ub))

#define mlk_assert_abs_bound_2d(ptr, len0, len1, value_abs_bd) \
  mlk_assert_abs_bound((ptr), ((len0) * (len1)), (value_abs_bd))

#elif defined(CBMC)
#include "cbmc.h"

#define mlk_assert(val) cassert(val)

#define mlk_assert_bound(ptr, len, value_lb, value_ub) \
  cassert(array_bound(((int16_t *)(ptr)), 0, (len), (value_lb), (value_ub)))

#define mlk_assert_abs_bound(ptr, len, value_abs_bd) \
  cassert(array_abs_bound(((int16_t *)(ptr)), 0, (len), (value_abs_bd)))

#define mlk_assert_bound_2d(ptr, M, N, value_lb, value_ub)              \
  cassert(forall(kN, 0, (M),                                            \
                 array_bound(&((int16_t (*)[(N)])(ptr))[kN][0], 0, (N), \
                             (value_lb), (value_ub))))

#define mlk_assert_abs_bound_2d(ptr, M, N, value_abs_bd)                    \
  cassert(forall(kN, 0, (M),                                                \
                 array_abs_bound(&((int16_t (*)[(N)])(ptr))[kN][0], 0, (N), \
                                 (value_abs_bd))))

#else

#define mlk_assert(val) \
  do                    \
  {                     \
  } while (0)
#define mlk_assert_bound(ptr, len, value_lb, value_ub) \
  do                                                   \
  {                                                    \
  } while (0)
#define mlk_assert_abs_bound(ptr, len, value_abs_bd) \
  do                                                 \
  {                                                  \
  } while (0)

#define mlk_assert_bound_2d(ptr, len0, len1, value_lb, value_ub) \
  do                                                             \
  {                                                              \
  } while (0)

#define mlk_assert_abs_bound_2d(ptr, len0, len1, value_abs_bd) \
  do                                                           \
  {                                                            \
  } while (0)

#endif
#endif
