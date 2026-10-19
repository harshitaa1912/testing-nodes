
#include "verify.h"

#if !defined(MLK_USE_ASM_VALUE_BARRIER) && \
    !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)

volatile uint64_t mlk_ct_opt_blocker_u64 = 0;

#else

MLK_EMPTY_CU(verify)

#endif
