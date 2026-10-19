

#ifndef MLK_CBMC_H
#define MLK_CBMC_H

#ifndef CBMC

#define __contract__(x)
#define __loop__(x)

#else

#define __contract__(x) x
#define __loop__(x) x

#define assigns(...) __CPROVER_assigns(__VA_ARGS__)

#define requires(...) __CPROVER_requires(__VA_ARGS__)
#define ensures(...) __CPROVER_ensures(__VA_ARGS__)

#define invariant(...) __CPROVER_loop_invariant(__VA_ARGS__)
#define decreases(...) __CPROVER_decreases(__VA_ARGS__)

#define cassert(x) __CPROVER_assert(x, "cbmc assertion failed")
#define assume(...) __CPROVER_assume(__VA_ARGS__)

#define return_value (__CPROVER_return_value)

#define object_whole(...) __CPROVER_object_whole(__VA_ARGS__)
#define memory_slice(...) __CPROVER_object_upto(__VA_ARGS__)

#define memory_no_alias(...) __CPROVER_is_fresh(__VA_ARGS__)
#define readable(...) __CPROVER_r_ok(__VA_ARGS__)
#define writeable(...) __CPROVER_w_ok(__VA_ARGS__)

#define MLK_MAX_BUFFER_SIZE (SIZE_MAX >> 12)

#define old(...) __CPROVER_old(__VA_ARGS__)
#define loop_entry(...) __CPROVER_loop_entry(__VA_ARGS__)

#define forall(qvar, qvar_lb, qvar_ub, predicate)                              \
  __CPROVER_forall                                                             \
  {                                                                            \
    uint32_t qvar;                                                             \
    ((uint32_t) (qvar_lb) <= (qvar) && (qvar) < (uint32_t) (qvar_ub)) ==> (predicate) \
  }

#define exists(qvar, qvar_lb, qvar_ub, predicate)                              \
  __CPROVER_exists                                                             \
  {                                                                            \
    uint32_t qvar;                                                             \
    ((uint32_t) (qvar_lb) <= (qvar) && (qvar) < (uint32_t) (qvar_ub)) && (predicate) \
  }

#define CBMC_CONCAT_(left, right) left##right
#define CBMC_CONCAT(left, right) CBMC_CONCAT_(left, right)

#define array_bound_core(qvar, qvar_lb, qvar_ub, array_var,            \
                         value_lb, value_ub)                           \
  __CPROVER_forall                                                     \
  {                                                                    \
    uint32_t qvar;                                                     \
    ((uint32_t) (qvar_lb) <= (qvar) && (qvar) < (uint32_t) (qvar_ub)) ==> \
        (((int)(value_lb) <= ((array_var)[(qvar)])) &&                 \
         (((array_var)[(qvar)]) < (int)(value_ub)))                    \
  }

#define array_bound(array_var, qvar_lb, qvar_ub, value_lb, value_ub)    \
  array_bound_core(CBMC_CONCAT(_cbmc_idx, __COUNTER__), (qvar_lb),      \
      (qvar_ub), (array_var), (value_lb), (value_ub))

#define array_unchanged_core(qvar, qvar_lb, qvar_ub, array_var)        \
  __CPROVER_forall                                                     \
  {                                                                    \
    uint32_t qvar;                                                     \
    ((uint32_t) (qvar_lb) <= (qvar) && (qvar) < (uint32_t) (qvar_ub)) ==> \
    ((array_var)[(qvar)]) == (old(* (int16_t (*)[(qvar_ub)])(array_var)))[(qvar)] \
  }

#define array_unchanged(array_var, N) \
    array_unchanged_core(CBMC_CONCAT(_cbmc_idx, __COUNTER__), 0, (N), (array_var))

#define array_unchanged_u64_core(qvar, qvar_lb, qvar_ub, array_var)    \
  __CPROVER_forall                                                     \
  {                                                                    \
    uint32_t qvar;                                                     \
    ((uint32_t) (qvar_lb) <= (qvar) && (qvar) < (uint32_t) (qvar_ub)) ==> \
    ((array_var)[(qvar)]) == (old(* (uint64_t (*)[(qvar_ub)])(array_var)))[(qvar)] \
  }

#define array_unchanged_u64(array_var, N) \
    array_unchanged_u64_core(CBMC_CONCAT(_cbmc_idx, __COUNTER__), 0, (N), (array_var))

#define array_unchanged_u8_core(qvar, array_var, N)                     \
  forall(qvar, 0, (N),                                                  \
    ((array_var)[(qvar)]) == (old(* (uint8_t (*)[(N)])(array_var)))[(qvar)])

#define array_unchanged_u8(array_var, N) \
    array_unchanged_u8_core(CBMC_CONCAT(_cbmc_idx, __COUNTER__), (array_var), (N))

#define array_zeroized_u8_core(qvar, array_var, N) \
    forall(qvar, 0, (N), ((array_var)[(qvar)]) == 0)

#define array_zeroized_u8(array_var, N) \
    array_zeroized_u8_core(CBMC_CONCAT(_cbmc_idx, __COUNTER__), (array_var), (N))

#define array_unchanged_or_zeroized_u8(array_var, N) \
  (array_unchanged_u8((array_var), (N)) || array_zeroized_u8((array_var), (N)))

#define array_abs_bound(arr, lb, ub, k) \
  array_bound((arr), (lb), (ub), -((int)(k)) + 1, (k))

#endif

#endif
