//#include <mach-o/loader.h>
#include "iemukern.h"
#include "log.h"

// This required macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires.
OSDefineMetaClassAndStructors(com_cod_iemukern, IOService)

// Define the driver's superclass.
#define super IOService


unsigned char shellcode[] __attribute__((section("__TEXT, __text"))) = {
    0x49, 0x83, 0xFF, 0x0A,
    0x75, 0x02,
    0x31, 0xC9,
    0x81, 0xF9, 0, 4, 0, 0,
    0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
    0xFF, 0xE1
};

bool com_cod_iemukern::init(OSDictionary *dict)
{
    bool result = super::init(dict);
    DbgPrint("[iemu] Initializing\n");
    return result;
}

void com_cod_iemukern::free(void)
{
    DbgPrint("[iemu] Freeing\n");
    super::free();
}

IOService *com_cod_iemukern::probe(IOService *provider, SInt32 *score)
{
    IOService *result = super::probe(provider, score);
    DbgPrint("[iemu] Probing\n");
    return result;
}

bool com_cod_iemukern::start(IOService *provider)
{
    //m_load_machfile_addr = 0;
    m_execsw_addr = 0;
    
    bool result = super::start(provider);
    if(!result) {
        DbgPrint("[iemu] super init fails.\n");
        return result;
    }
    DbgPrint("[iemu] Starting\n");
    if(!init_kernel_info()) return false;
    
    struct hookp hookp;
    hookp.current_map = (fn_current_map)solve_kernel_symbol("_current_map");
    hookp.real_exception_deliver = (fn_exception_deliver)solve_kernel_symbol("_exception_deliver");
    hookp.thread_adjuserstack = (fn_thread_adjuserstack)solve_kernel_symbol("_thread_adjuserstack");
    if(!init_hooks(&hookp)) {
        DbgPrint("[iemu] init_hooks fails...\n");
        return false;
    }
    
    patch_load_macho();
    
    DbgPrint("[iemu] start completed!\n");
    return result;
}

void com_cod_iemukern::stop(IOService *provider)
{
    DbgPrint("[iemu] Stopping\n");
    unpatch_load_macho();
    cleanup_kernel_info();
    super::stop(provider);
}


