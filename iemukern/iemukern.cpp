//#include <mach-o/loader.h>
#include "iemukern.h"
#include "log.h"
#include "MachOLocator.h"
#include <i386/cpuid.h>

struct kernel_info com_cod_iemukern::m_kernel_info;
//unsigned char m_load_machfile_bytes[5];
//mach_vm_address_t m_load_machfile_addr;
mach_vm_address_t com_cod_iemukern::m_execsw_addr;

uint8_t com_cod_iemukern::m_exception_triage_backup[5];
mach_vm_address_t com_cod_iemukern::m_exception_triage_hook;

mach_vm_address_t com_cod_iemukern::m_final_test;

// This required macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires.
OSDefineMetaClassAndStructors(com_cod_iemukern, IOService)

// Define the driver's superclass.
#define super IOService

int com_cod_iemukern::smap_supported;
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
    uint32_t data[4];
    m_execsw_addr = 0;
    do_cpuid(7, data);
    
    smap_supported = ((CPUID_LEAF7_FEATURE_SMAP & data[ebx]) != 0);
    
    bool result = super::start(provider);
    if(!result) {
        DbgPrint("[iemu] super init fails.\n");
        return result;
    }

    uintptr_t retaddr = (uintptr_t)__builtin_return_address(0);
    DbgPrint("[iemu] Starting\n");
    if(!init_kernel_info(retaddr)) {
        DbgPrint("init_kernel_info fails.\n");
        return false;
    }

    struct hookp hookp;
    hookp.current_map = (fn_current_map)solve_kernel_symbol("_current_map");
    if(!init_hooks(&hookp)) {
        DbgPrint("[iemu] init_hooks fails...\n");
        return false;
    }
    
    if(!patch_load_macho()) {
        DbgPrint("[iemu] cannot patch load macho.\n");
        return false;
    }
    if(!patch_custom_kernel()) {      // This allows us to use a original kernel instead of the open-source buggy one,
                                // simply because Apple eats shit.
        DbgPrint("[iemu] cannot patch kernel.\n");
        return false;
    }
    
    DbgPrint("[iemu] start completed!\n");
    return result;
}

void com_cod_iemukern::stop(IOService *provider)
{
    DbgPrint("[iemu] Stopping\n");
    unpatch_load_macho();
    unpatch_custom_kernel();
    cleanup_kernel_info();
    super::stop(provider);
}

typedef void *vm_page_t;
typedef void *pmap_t;
typedef uint16_t vm_tag_t;

struct vm_object_fault_info {
    int             interruptible;
    uint32_t        user_tag;
    vm_size_t       cluster_size;
    vm_behavior_t   behavior;
    vm_map_offset_t lo_offset;
    vm_map_offset_t hi_offset;
    unsigned int
    /* boolean_t */ no_cache:1,
    /* boolean_t */ stealth:1,
    /* boolean_t */ io_sync:1,
    /* boolean_t */ cs_bypass:1,
    /* boolean_t */ pmap_cs_associated:1,
    /* boolean_t */ mark_zf_absent:1,
    /* boolean_t */ batch_pmap_op:1,
    /* boolean_t */ resilient_media:1,
    /* boolean_t */ no_copy_on_read:1,
        __vm_object_fault_info_unused_bits:23;
    int             pmap_options;
};

typedef struct vm_object_fault_info *vm_object_fault_info_t;

extern "C" kern_return_t
orig_vm_fault_enter(vm_page_t m,
                  pmap_t pmap,
                  vm_map_offset_t vaddr,
                  vm_prot_t prot,
                  vm_prot_t caller_prot,
                  boolean_t wired,
                  boolean_t change_wiring,
                  vm_tag_t wire_tag,
                  vm_object_fault_info_t fault_info,
                  boolean_t *need_retry,
                  int *type_of_fault);
extern uint64_t next_vm_fault_enter;

static kern_return_t
my_vm_fault_enter(vm_page_t m,
                  pmap_t pmap,
                  vm_map_offset_t vaddr,
                  vm_prot_t prot,
                  vm_prot_t caller_prot,
                  boolean_t wired,
                  boolean_t change_wiring,
                  vm_tag_t wire_tag,
                  vm_object_fault_info_t fault_info,
                  boolean_t *need_retry,
                  int *type_of_fault)
{
    fault_info->cs_bypass = 1;
    return orig_vm_fault_enter(m, pmap, vaddr, prot, caller_prot, wired, change_wiring, wire_tag, fault_info, need_retry, type_of_fault);
}

bool com_cod_iemukern::patch_custom_kernel()
{
    m_pcs_system_enforcement_enable = (int *)
        solve_kernel_symbol("_cs_system_enforcement_enable");
    m_pcs_process_enforcement_enable = (int *)
        solve_kernel_symbol("_cs_process_enforcement_enable");
    m_pcs_library_val_enable = (int *)solve_kernel_symbol("_cs_library_val_enable");
    m_pcs_debug = (int *)solve_kernel_symbol("_cs_debug");
    m_cs_system_enforcement = (void *)solve_kernel_symbol("_cs_system_enforcement");
    m_cs_process_enforcement = (void *)solve_kernel_symbol("_cs_process_enforcement");
    m_cs_validate_range = (void *)solve_kernel_symbol("_cs_validate_range");
    m_csr_check = (void *)solve_kernel_symbol("_csr_check");
    m_vm_fault_enter = (void *)solve_kernel_symbol("_vm_fault_enter");
    
    uint8_t x64_jmp[PATCH_X64_JMP_SIZE] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0 };
    uint8_t retn_0[PATCH_RETN_0_SIZE] = { 0x33, 0xC0, 0xC3 };
    uint8_t cs_validate_range_patch[PATCH_CS_VALIDATE_RANGE_SIZE] = {
        0x41, 0xC7, 1, 0, 0, 0, 0,  // mov dword ptr [r9], 0
        0x33, 0xC0,                 // xor eax, eax
        0xFF, 0xC0,                 // inc eax
        0xC3                        // retn
    };
    
    m_cs_system_enforcement_enable = *m_pcs_system_enforcement_enable;
    m_cs_process_enforcement_enable = *m_pcs_process_enforcement_enable;
    
    m_cs_library_val_enable = *m_pcs_library_val_enable;
    
    
    //m_cs_debug = *m_pcs_debug;
    
    
    next_vm_fault_enter = (uint64_t)((uint8_t *)m_vm_fault_enter + sizeof(x64_jmp));
    *(uint64_t *)(x64_jmp + 2) = (uint64_t)my_vm_fault_enter;   // There is a hook stub designed for Catalina 10.15.4,
                                                                // Use with caution when it is for other versions of kernels.
    
    memcpy(m_vm_fault_enter_backup, m_vm_fault_enter, sizeof(x64_jmp));
    memcpy(m_cs_system_enforcement_backup, m_cs_system_enforcement, sizeof(retn_0));
    memcpy(m_cs_process_enforcement_backup, m_cs_process_enforcement, sizeof(retn_0));
    memcpy(m_cs_validate_range_backup, m_cs_validate_range, sizeof(cs_validate_range_patch));
    memcpy(m_csr_check_backup, m_csr_check, sizeof(retn_0));
    
    InMemoryMachO *amfiKext = findKextByName("com.apple.driver.AppleMobileFileIntegrity");
    
    if(nullptr == amfiKext) {
        DbgPrint("[iemu] Did not find AMFI.");
        return false;
    } else {
        m_pallowInvalidSignatures = (uint8_t *)amfiKext->solveSymbol("_allowInvalidSignatures");
        m_pallowEverything = (uint8_t *)amfiKext->solveSymbol("_allowEverything");
        m_pcsEnforcementDisable = (uint8_t *)amfiKext->solveSymbol("_csEnforcementDisable");
        
        m_allowInvalidSignatures = *m_pallowInvalidSignatures;
        m_allowEverything = *m_pallowEverything;
        m_csEnforcementDisable = *m_pcsEnforcementDisable;
        
        delete amfiKext;
    }
    
    disable_interrupts();
    disable_wp();
    
    *m_pcs_system_enforcement_enable = 0;
    *m_pcs_process_enforcement_enable = 0;
    *m_pcs_library_val_enable = 0;
    //*m_pcs_debug = 20;
    
    memcpy(m_vm_fault_enter, x64_jmp, sizeof(x64_jmp));
    memcpy(m_cs_system_enforcement, retn_0, sizeof(retn_0));
    memcpy(m_cs_process_enforcement, retn_0, sizeof(retn_0));
    memcpy(m_cs_validate_range, cs_validate_range_patch, sizeof(cs_validate_range_patch));
    memcpy(m_csr_check, retn_0, sizeof(retn_0));
    
    *m_pallowInvalidSignatures = 1;
    *m_pallowEverything = 1;
    *m_pcsEnforcementDisable = 1;
    
    enable_wp();
    enable_interrupts();
    
    return true;
}

bool com_cod_iemukern::unpatch_custom_kernel()
{
    disable_interrupts();
    disable_wp();
    
    *m_pcs_system_enforcement_enable = m_cs_system_enforcement_enable;
    *m_pcs_process_enforcement_enable = m_cs_process_enforcement_enable;
    
    *m_pcs_library_val_enable = m_cs_library_val_enable;
    //*m_pcs_debug = m_cs_debug;
    
    memcpy(m_vm_fault_enter, m_vm_fault_enter_backup, sizeof(m_vm_fault_enter_backup));
    memcpy(m_cs_system_enforcement, m_cs_system_enforcement_backup, sizeof(m_cs_system_enforcement_backup));
    memcpy(m_cs_process_enforcement, m_cs_process_enforcement_backup, sizeof(m_cs_process_enforcement_backup));
    memcpy(m_cs_validate_range, m_cs_validate_range_backup, sizeof(m_cs_validate_range_backup));
    memcpy(m_csr_check, m_csr_check_backup, sizeof(m_csr_check_backup));
    
    *m_pallowInvalidSignatures = m_allowInvalidSignatures;
    *m_pallowEverything = m_allowEverything;
    *m_pcsEnforcementDisable = m_csEnforcementDisable;
    
    enable_wp();
    enable_interrupts();
    
    return true;
}
