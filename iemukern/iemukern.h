#ifndef _IEMUKERN_H_
#define _IEMUKERN_H_

#include <IOKit/IOService.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <IOKit/IOLib.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>

#include "idt.h"
#include "vfs.h"
extern "C" {
#include "cpu_protection.h"
#include "hooks.h"
};

#define MACH_KERNEL         "/System/Library/Kernels/kernel"      // location of kernel in filesystem
#include "log.h"


struct kernel_info
{
    mach_vm_address_t running_text_addr; // the address of running __TEXT segment
    mach_vm_address_t disk_text_addr;    // the same address at /mach_kernel in filesystem
    mach_vm_address_t kaslr_slide;       // the kernel aslr slide, computed as the difference between above's addresses
    void *linkedit_buf;                  // pointer to __LINKEDIT buffer containing symbols to solve
    uint64_t linkedit_fileoff;           // __LINKEDIT file offset so we can read
    uint64_t linkedit_size;
    uint32_t symboltable_fileoff;        // file offset to symbol table - used to position inside the __LINKEDIT buffer
    uint32_t symboltable_nr_symbols;
    uint32_t stringtable_fileoff;        // file offset to string table
    uint32_t stringtable_size;
    // other info from the header we might need
    uint64_t text_size;                  // size of __text section to disassemble
    struct mach_header_64 *mh;           // ptr to mach-o header of running kernel
};

extern unsigned char shellcode[];

class com_cod_iemukern : public IOService
{
    OSDeclareDefaultStructors(com_cod_iemukern)
public:
    virtual bool init(OSDictionary *dictionary = 0) override;
    virtual void free(void) override;
    virtual IOService *probe(IOService *provider, SInt32 *score) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    
private:
    bool patch_custom_kernel();
    bool unpatch_custom_kernel();
    
    static bool patch_load_macho()
    {
        mach_vm_address_t addr_execsw = solve_kernel_symbol("_execsw");
        if(!addr_execsw) {
            DbgPrint("[iemu] cannot solve _execsw.\n");
            return false;
        }
        g_pfnexec_mach_imgact = ((struct execsw *)addr_execsw)->ex_imgact;
        disable_interrupts();
        disable_wp();
        ((struct execsw *)addr_execsw)->ex_imgact = pre_exec_mach_imgact;
        enable_wp();
        enable_interrupts();
        m_execsw_addr = addr_execsw;
        
        return true;
    }
    
    static bool unpatch_load_macho()
    {
        if(m_execsw_addr) {
            disable_interrupts();
            disable_wp();
            ((struct execsw *)m_execsw_addr)->ex_imgact = g_pfnexec_mach_imgact;
            enable_wp();
            enable_interrupts();
        }
        
        return true;
    }
    
    static bool init_kernel_info(uintptr_t slice_of_kernel)
    {
        kern_return_t error = 0;
        // lookup vnode for /mach_kernel
        vnode_t kernel_vnode = NULLVP;
        error = vnode_lookup(MACH_KERNEL, 0, &kernel_vnode, vfs_context_current());
        if (error) {
            DbgPrint("[iemu] error vnode_lookup: %s, %d\n", MACH_KERNEL, error);
            return false;
        }
        
        void *kernel_header = IOMalloc(PAGE_SIZE_64 * 2);
        if (kernel_header == NULL) {
            DbgPrint("[iemu] error IOMalloc, out of memory.\n");
            goto failure;
        }
        
        // read and process kernel header from filesystem
        error = vfs_read_file(kernel_header, kernel_vnode, 0, PAGE_SIZE_64 * 2, vfs_context_current());
        if (error) goto failure;
        
        if(!process_kernel_mach_header(kernel_header, &m_kernel_info)) goto failure;
        
        // compute kaslr slide
        get_running_text_address(&m_kernel_info, slice_of_kernel);
        
        m_kernel_info.kaslr_slide = m_kernel_info.running_text_addr - m_kernel_info.disk_text_addr;
        
        DbgPrint("[iemu] kernel aslr slide is 0x%llx\n", m_kernel_info.kaslr_slide);
        // we know the location of linkedit and offsets into symbols and their strings
        // now we need to read linkedit into a buffer so we can process it later
        // __LINKEDIT total size is around 1MB
        // we should free this buffer later when we don't need anymore to solve symbols
        m_kernel_info.linkedit_buf = IOMalloc(m_kernel_info.linkedit_size);
        if (m_kernel_info.linkedit_buf == NULL) {
            DbgPrint("[iemu] IOMalloc failed with linkedit buf");
            goto failure;
        }
        // read linkedit from filesystem
        error = vfs_read_file(m_kernel_info.linkedit_buf, kernel_vnode, m_kernel_info.linkedit_fileoff, m_kernel_info.linkedit_size, vfs_context_current());
        if (error) goto failure;
        
    success:
        IOFree(kernel_header, PAGE_SIZE_64 * 2);
        // drop the iocount due to vnode_lookup()
        // we must do this else machine will block on shutdown/reboot
        vnode_put(kernel_vnode);
        return true;
        
    failure:
        DbgPrint("[iemu] %s failure...\n", __FUNCTION__);
        if (m_kernel_info.linkedit_buf != NULL)
            IOFree(m_kernel_info.linkedit_buf, m_kernel_info.linkedit_size);
        if(kernel_header)
            IOFree(kernel_header, PAGE_SIZE_64 * 2);
        vnode_put(kernel_vnode);
        return false;
    }
    
    /*
     * cleanup the kernel info buffer to avoid memory leak.
     * there's nothing else to cleanup here, for now
     */
    static bool
    cleanup_kernel_info()
    {
        if (m_kernel_info.linkedit_buf != NULL) IOFree(m_kernel_info.linkedit_buf, m_kernel_info.linkedit_size);
        return true;
    }
    
    /*
     * retrieve necessary mach-o header information from the kernel buffer
     * stored at our kernel_info structure
     */
    static bool
    process_kernel_mach_header(void *kernel_header, struct kernel_info *kinfo)
    {
        struct mach_header_64 *mh = (struct mach_header_64*)kernel_header;
        // test if it's a valid mach-o header (or appears to be)
        if (mh->magic != MH_MAGIC_64) return false;
        
        struct load_command *load_cmd = NULL;
        // point to the first load command
        char *load_cmd_addr = (char*)kernel_header + sizeof(struct mach_header_64);
        // iterate over all load cmds and retrieve required info to solve symbols
        // __LINKEDIT location and symbol/string table location
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            load_cmd = (struct load_command*)load_cmd_addr;
            if (load_cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
                // use this one to retrieve the original vm address of __TEXT so we can compute kernel aslr slide
                if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
                    kinfo->disk_text_addr = seg_cmd->vmaddr;
                    // lookup the __text section - we want the size which can be retrieve here or from the running version
                    char *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
                    struct section_64 *section_cmd = NULL;
                    // iterate thru all sections
                    for (uint32_t x = 0; x < seg_cmd->nsects; x++) {
                        section_cmd = (struct section_64*)section_addr;
                        if (strncmp(section_cmd->sectname, "__text", 16) == 0) {
                            kinfo->text_size = section_cmd->size;
                            break;
                        }
                        section_addr += sizeof(struct section_64);
                    }
                }
                else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0) {
                    kinfo->linkedit_fileoff = seg_cmd->fileoff;
                    kinfo->linkedit_size    = seg_cmd->filesize;
                }
            }
            // table information available at LC_SYMTAB command
            else if (load_cmd->cmd == LC_SYMTAB) {
                struct symtab_command *symtab_cmd = (struct symtab_command*)load_cmd;
                kinfo->symboltable_fileoff    = symtab_cmd->symoff;
                kinfo->symboltable_nr_symbols = symtab_cmd->nsyms;
                kinfo->stringtable_fileoff    = symtab_cmd->stroff;
                kinfo->stringtable_size       = symtab_cmd->strsize;
            }
            load_cmd_addr += load_cmd->cmdsize;
        }
        return true;
    }
    
    /*
     * retrieve the __TEXT address of current loaded kernel so we can compute the KASLR slide
     * also the size of __text
     */
    static void
    get_running_text_address(struct kernel_info *kinfo, uintptr_t slice_of_kernel)
    {
        // retrieves the address of the IDT
        mach_vm_address_t idt_address = 0;
        get_addr_idt(&idt_address);
        // calculate the address of the int80 handler
        mach_vm_address_t addr_kernel = slice_of_kernel;
        //calculate_int80address(idt_address);
        
        //High Sierra does not use in-kernel interrupt handler.
        
        // search backwards for the kernel base address (mach-o header)
        mach_vm_address_t kernel_base = find_kernel_base(addr_kernel);
        if (kernel_base != 0) {
            // get the vm address of __TEXT segment
            struct mach_header_64 *mh = (struct mach_header_64*)kernel_base;
            struct load_command *load_cmd = NULL;
            char *load_cmd_addr = (char*)kernel_base + sizeof(struct mach_header_64);
            for (uint32_t i = 0; i < mh->ncmds; i++) {
                load_cmd = (struct load_command*)load_cmd_addr;
                if (load_cmd->cmd == LC_SEGMENT_64) {
                    struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
                    if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
                        kinfo->running_text_addr = seg_cmd->vmaddr;
                        kinfo->mh = mh;
                        break;
                    }
                }
                load_cmd_addr += load_cmd->cmdsize;
            }
        }
    }

    /*
     * calculate the address of the kernel int80 handler
     * using the IDT array
     */
    static mach_vm_address_t
    calculate_int80address(const mach_vm_address_t idt_address)
    {
        // find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s
        struct descriptor_idt *int80_descriptor;
        mach_vm_address_t int80_address;
        // we need to compute the address, it's not direct
        // extract the stub address
        // retrieve the descriptor for interrupt 0x80
        // the IDT is an array of descriptors
        int80_descriptor = (struct descriptor_idt*)(idt_address+sizeof(struct descriptor_idt)*0x80);
        uint64_t high = (unsigned long)int80_descriptor->offset_high << 32;
        uint32_t middle = (unsigned int)int80_descriptor->offset_middle << 16;
        int80_address = (mach_vm_address_t)(high + middle + int80_descriptor->offset_low);

        DbgPrint("[iemu] Address of interrupt 80 stub is %llx\n", int80_address);
        return int80_address;
    }
    
    /*
     * find the kernel base address (mach-o header)
     * by searching backwards using the int80 handler as starting point
     */
    static mach_vm_address_t
    find_kernel_base(const mach_vm_address_t int80_address)
    {
        mach_vm_address_t temp_address = int80_address;
        struct segment_command_64 *segment_command = NULL;
        
        while (temp_address > 0) {
            if (*(uint32_t*)(temp_address) == MH_MAGIC_64 && ((struct mach_header_64*)temp_address)->filetype == MH_EXECUTE) {
                // make sure it's the header and not some reference to the MAGIC number
                segment_command = (struct segment_command_64*)(temp_address + sizeof(struct mach_header_64));
                if (strncmp(segment_command->segname, "__TEXT", 16) == 0) {
                    DbgPrint("[iemu] Found running kernel mach-o header address at 0x%llx\n", temp_address);
                    return temp_address;
                }
            }
            // check for int overflow
            if (temp_address - 1 > temp_address) break;
            temp_address--;
        }
        return 0;
    }
public:
    static int smap_supported;
    /*
     * function to solve a kernel symbol
     */
    static mach_vm_address_t
    solve_kernel_symbol(const char *symbol_to_solve)
    {
        struct nlist_64 *nlist = NULL;
        
        if (m_kernel_info.linkedit_buf == NULL) return 0;
        
        // symbols and strings offsets into LINKEDIT
        // we just read the __LINKEDIT but fileoff values are relative to the full /mach_kernel
        // subtract the base of LINKEDIT to fix the value into our buffer
        mach_vm_address_t symbol_off = m_kernel_info.symboltable_fileoff - m_kernel_info.linkedit_fileoff;
        mach_vm_address_t string_off = m_kernel_info.stringtable_fileoff - m_kernel_info.linkedit_fileoff;
        // search for the symbol and get its location if found
        for (uint32_t i = 0; i < m_kernel_info.symboltable_nr_symbols; i++) {
            // get the pointer to the symbol entry and extract its symbol string
            nlist = (struct nlist_64*)((char*)m_kernel_info.linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
            char *symbol_string = ((char*)m_kernel_info.linkedit_buf + string_off + nlist->n_un.n_strx);
            // find if symbol matches
            // XXX: we could obfuscate this and make it faster with some hash algo
            if (strncmp(symbol_to_solve, symbol_string, strlen(symbol_to_solve)) == 0) {
                DbgPrint("[iemu] found symbol %s at 0x%llx\n", symbol_to_solve, nlist->n_value);
                // the symbols values are without kernel ASLR so we need to add it
                return (nlist->n_value + m_kernel_info.kaslr_slide);
            }
        }
        // failure
        return 0;
    }
    
private:
    // private structures
    static struct kernel_info m_kernel_info;
    //unsigned char m_load_machfile_bytes[5];
    //mach_vm_address_t m_load_machfile_addr;
    static mach_vm_address_t m_execsw_addr;
    
    static uint8_t m_exception_triage_backup[5];
    static mach_vm_address_t m_exception_triage_hook;
    
    static mach_vm_address_t m_final_test;
    
    // All about the patches in the kernel
    
#define PATCH_X64_JMP_SIZE              12
#define PATCH_RETN_0_SIZE               3
#define PATCH_CS_VALIDATE_RANGE_SIZE    12
    
    int *m_pcs_system_enforcement_enable;
    int *m_pcs_process_enforcement_enable;
    int m_cs_system_enforcement_enable;
    int m_cs_process_enforcement_enable;
    
    int *m_pcs_library_val_enable;
    int m_cs_library_val_enable;
    
    int *m_pcs_debug;
    int m_cs_debug;
    
    void *m_vm_fault_enter;
    uint8_t m_vm_fault_enter_backup[PATCH_X64_JMP_SIZE];
    
    void *m_cs_system_enforcement;
    void *m_cs_process_enforcement;
    void *m_cs_validate_range;
    uint8_t m_cs_system_enforcement_backup[PATCH_RETN_0_SIZE];
    uint8_t m_cs_process_enforcement_backup[PATCH_RETN_0_SIZE];
    uint8_t m_cs_validate_range_backup[PATCH_CS_VALIDATE_RANGE_SIZE];
    
    void *m_csr_check;
    uint8_t m_csr_check_backup[PATCH_RETN_0_SIZE];
    
    uint8_t *m_pallowInvalidSignatures,
            *m_pallowEverything,
            *m_pcsEnforcementDisable;
    
    uint8_t m_allowInvalidSignatures;
    uint8_t m_allowEverything;
    uint8_t m_csEnforcementDisable;
    
};

#endif

