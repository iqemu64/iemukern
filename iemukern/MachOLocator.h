
#ifndef MachOLocator_h
#define MachOLocator_h

#include "InMemoryMachO.h"
#include <IOKit/IOLib.h>

InMemoryMachO *findKextByName(const char *name);
InMemoryMachO *findDyldInUser(bool bit64, task_t task);

#endif /* MachOLocator_h */
