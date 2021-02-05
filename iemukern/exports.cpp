
#include "exports.h"
#include "iemukern.h"
#include <libkern/OSAtomic.h>

typedef task_t (*fn_port_name_to_task)(mach_port_name_t name);
typedef void *(*fn_get_bsdtask_info)(task_t task);
typedef vm_map_t (*fn_get_task_map)(task_t t);
typedef vm_map_t (*fn_vm_map_switch)(vm_map_t map);
typedef kern_return_t (*fn_port_name_to_semaphore)(mach_port_name_t name, semaphore_t *semaphore);
typedef void (*fn_semaphore_dereference)(semaphore_t semaphore);
typedef task_t (*fn_get_threadtask)(thread_t thread);

extern "C"
task_t my_port_name_to_task(mach_port_name_t name)
{
    static fn_port_name_to_task s_f = NULL;
    if(NULL == s_f) {
        fn_port_name_to_task f = (fn_port_name_to_task)com_cod_iemukern::solve_kernel_symbol("_port_name_to_task");
        OSCompareAndSwapPtr(NULL, (void *)f, &s_f);
    }
    
    return s_f(name);
}

extern "C"
void *my_get_bsdtask_info(task_t task)
{
    static fn_get_bsdtask_info s_f = NULL;
    if(NULL == s_f) {
        fn_get_bsdtask_info f = (fn_get_bsdtask_info)com_cod_iemukern::solve_kernel_symbol("_get_bsdtask_info");
        OSCompareAndSwapPtr(NULL, (void *)f, &s_f);
    }
    return s_f(task);
}

extern "C"
task_t my_get_threadtask(thread_t thread)
{
    static fn_get_threadtask s_f = NULL;
    if(NULL == s_f) {
        fn_get_threadtask f = (fn_get_threadtask)com_cod_iemukern::solve_kernel_symbol("_get_threadtask");
        OSCompareAndSwapPtr(NULL, (void *)f, &s_f);
    }
    return s_f(thread);
}

extern "C"
vm_map_t my_get_task_map(task_t t)
{
    static fn_get_task_map s_f = NULL;
    if(NULL == s_f) {
        fn_get_task_map f = (fn_get_task_map)com_cod_iemukern::solve_kernel_symbol("_get_task_map");
        OSCompareAndSwapPtr(NULL, (void *)f, &s_f);
    }
    return s_f(t);
}

extern "C"
vm_map_t my_vm_map_switch(vm_map_t map)
{
    static fn_vm_map_switch s_f = NULL;
    if(NULL == s_f) {
        fn_vm_map_switch f = (fn_vm_map_switch)com_cod_iemukern::solve_kernel_symbol("_vm_map_switch");
        OSCompareAndSwapPtr(NULL, (void *)f, &s_f);
    }
    return s_f(map);
}

extern "C"
kern_return_t my_port_name_to_semaphore(mach_port_name_t name, semaphore_t *semaphore)
{
    static fn_port_name_to_semaphore s_f = NULL;
    if(NULL == s_f) {
        fn_port_name_to_semaphore f = (fn_port_name_to_semaphore)com_cod_iemukern::solve_kernel_symbol("_port_name_to_semaphore");
        OSCompareAndSwapPtr(NULL, (void *)f, &s_f);
    }
    return s_f(name, semaphore);
}


extern "C"
void my_semaphore_dereference(semaphore_t semaphore)
{
    static fn_semaphore_dereference s_f = NULL;
    if(NULL == s_f) {
        fn_semaphore_dereference f = (fn_semaphore_dereference)com_cod_iemukern::solve_kernel_symbol("_semaphore_dereference");
        OSCompareAndSwapPtr(NULL, (void *)f, &s_f);
    }
    return s_f(semaphore);
}
