
#ifndef exports_h
#define exports_h

#include <IOKit/IOLib.h>
#include <kern/task.h>

#ifdef __cplusplus
extern "C"
#endif
__attribute__ ((visibility("default")))
task_t my_port_name_to_task(mach_port_name_t name);

#ifdef __cplusplus
extern "C"
#endif
__attribute__ ((visibility("default")))
void *my_get_bsdtask_info(task_t task);

#ifdef __cplusplus
extern "C"
#endif
__attribute__ ((visibility("default")))
task_t my_get_threadtask(thread_t thread);

#ifdef __cplusplus
extern "C"
#endif
__attribute__ ((visibility("default")))
vm_map_t my_get_task_map(task_t t);

#ifdef __cplusplus
extern "C"
#endif
__attribute__ ((visibility("default")))
vm_map_t my_vm_map_switch(vm_map_t map);

#ifdef __cplusplus
extern "C"
#endif
__attribute__ ((visibility("default")))
kern_return_t my_port_name_to_semaphore(mach_port_name_t name, semaphore_t *semaphore);

#ifdef __cplusplus
extern "C"
#endif
__attribute__ ((visibility("default")))
void my_semaphore_dereference(semaphore_t semaphore);

#endif /* exports_h */
