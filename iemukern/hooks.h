
#ifndef iemukern_hooks_h
#define iemukern_hooks_h

//#define IOS_SIMULATOR_DEBUG

#include <sys/imgact.h>


#define MH_EMULATOR                0x10000000
/* using an undefined subtype could cause binary non-debuggable,
 * which is not a issue under release mode. consider using this
 * as an identifier of the emulator in the final product.
 */
#define CPU_SUBTYPE_ARM_EMULATOR   9527

typedef int (*ex_imgact)(struct image_params *);
struct execsw {
    ex_imgact ex_imgact;
    const char *ex_name;
};

typedef vm_map_t (* fn_current_map)();
typedef kern_return_t (* fn_exception_deliver)(
                                               thread_t *thread,
                                               exception_type_t exception,
                                               mach_exception_data_t code,
                                               mach_msg_type_number_t codeCnt,
                                               void *excp,
                                               lck_mtx_t   *mutex);
typedef uint64_t (* fn_thread_adjuserstack)(thread_t thread, int adjust);

extern ex_imgact g_pfnexec_mach_imgact;
int pre_exec_mach_imgact(struct image_params *imgp);

struct hookp {
    fn_current_map current_map;
    fn_exception_deliver real_exception_deliver;
    fn_thread_adjuserstack thread_adjuserstack;
};



kern_return_t my_exception_deliver(
    thread_t *thread,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    void *excp,
    lck_mtx_t   *mutex);

bool init_hooks(struct hookp *hookp);

#endif
