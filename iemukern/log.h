
#ifndef log_h
#define log_h

#include <IOKit/IOLib.h>

#if DEBUG == 1
#   define DbgPrint(...)      IOLog(__VA_ARGS__)
#else
#   define DbgPrint(...)    ((void)0)
#endif

#endif /* log_h */
