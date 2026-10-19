
#ifndef MLK_CONTEXT_H
#define MLK_CONTEXT_H

#ifdef MLK_CONFIG_CONTEXT_PARAMETER
#define MLK_CONTEXT_PARAMETERS_0(context) (context)
#define MLK_CONTEXT_PARAMETERS_1(arg0, context) (arg0, context)
#define MLK_CONTEXT_PARAMETERS_2(arg0, arg1, context) (arg0, arg1, context)
#define MLK_CONTEXT_PARAMETERS_3(arg0, arg1, arg2, context) \
  (arg0, arg1, arg2, context)
#define MLK_CONTEXT_PARAMETERS_4(arg0, arg1, arg2, arg3, context) \
  (arg0, arg1, arg2, arg3, context)
#else
#define MLK_CONTEXT_PARAMETERS_0(context) ()
#define MLK_CONTEXT_PARAMETERS_1(arg0, context) (arg0)
#define MLK_CONTEXT_PARAMETERS_2(arg0, arg1, context) (arg0, arg1)
#define MLK_CONTEXT_PARAMETERS_3(arg0, arg1, arg2, context) (arg0, arg1, arg2)
#define MLK_CONTEXT_PARAMETERS_4(arg0, arg1, arg2, arg3, context) \
  (arg0, arg1, arg2, arg3)
#endif

#if defined(MLK_CONFIG_CONTEXT_PARAMETER)
#define MLK_CONTEXT_UNUSED(context) ((void)(context))
#else
#define MLK_CONTEXT_UNUSED(context) ((void)0)
#endif

#if defined(MLK_CONFIG_CONTEXT_PARAMETER_TYPE) != \
    defined(MLK_CONFIG_CONTEXT_PARAMETER)
#error MLK_CONFIG_CONTEXT_PARAMETER_TYPE must be defined if and only if MLK_CONFIG_CONTEXT_PARAMETER is defined
#endif

#endif
