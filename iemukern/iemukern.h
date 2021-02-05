#include <IOKit/IOService.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <IOKit/IOLib.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>

#include "idt.h"
extern "C" {
#include "cpu_protection.h"
#include "hooks.h"
};

#include "log.h"

#define MACH_KERNEL         "/mach_kernel"      // location of kernel in filesystem

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
    bool patch_load_macho()
    {
        /*
        mach_vm_address_t addr = solve_kernel_symbol("_load_machfile");
        unsigned char ucjmp[5] = { 0xE9 };
        *(unsigned int *)(ucjmp + 1) = (unsigned int)
            ((mach_vm_address_t)_load_machfile - addr - 5);
        
        g_load_machfile_ret = addr + 6;
        m_load_machfile_addr = addr;
        
        disable_interrupts();
        disable_wp();
        
        memcpy(m_load_machfile_bytes, (const void *)addr, sizeof(m_load_machfile_bytes));
        memcpy((void *)addr, ucjmp, sizeof(ucjmp));
        
        enable_wp();
        enable_interrupts();*/
        
        mach_vm_address_t addr_execsw = solve_kernel_symbol("_execsw");
        if(!addr_execsw) {
            DbgPrint("[iemu] cannot solve _execsw.\n");
            return false;
        }
        g_pfnexec_mach_imgact = ((struct execsw *)addr_execsw)->ex_imgact;
        disable_interrupts();
        ((struct execsw *)addr_execsw)->ex_imgact = pre_exec_mach_imgact;
        enable_interrupts();
        m_execsw_addr = addr_execsw;
        
        /* here seals the patch of exception pass.*
        mach_vm_address_t addr_exception = solve_kernel_symbol("_exception_triage");
        if(!addr_exception) {
            DbgPrint("[iemu] iemu: cannot solve _exception_triage.\n");
            return false;
        }
        uint8_t pattern[] = { 0x74, 0x3A, 0x3D, 0x09, 0x40, 0 };
        uint8_t patch[] = { 0xE8, 0, 0, 0, 0 };
        // pattern is version critical, so it is only used
        // for debug use. It will disappear in shipped version.
        int i = 0;
        for(i = 0; i < 200; i ++) {
            if(!memcmp((void *)(addr_exception + i), pattern, sizeof(pattern))) {
                break;
            }
        }
        if(200 == i) {
            DbgPrint("[iemu] pattern for exception_triage not found, brace yourselves for a panic.\n");
        } else {
            DbgPrint("[iemu] the je in exception_triage found: %llx\n", addr_exception + i);
        }
        
        m_exception_triage_hook = addr_exception + i - 7;
        *(uint32_t *)(patch + 1) = (uint32_t)
            ((mach_vm_address_t)my_exception_deliver - m_exception_triage_hook - 5);
        
        disable_interrupts();
        disable_wp();
        memcpy(m_exception_triage_backup, (const void *)m_exception_triage_hook, sizeof(m_exception_triage_backup));
        memcpy((void *)m_exception_triage_hook, patch, sizeof(patch));
        enable_wp();
        enable_interrupts();
        //*/
        /*
        m_final_test = solve_kernel_symbol("_issignal_locked");
        if(!m_final_test) {
            DbgPrint("[iemu] iqemu: cannot solve _issignal_locked.\n");
            return false;
        }
        uint8_t pattern2[] = { 0x81, 0xF9, 0, 4, 0, 0, 0x0F, 0x85, 0xBD, 1, 0, 0 };
        
        for(i = 200; i < 1000; i ++) {
            if(!memcmp((void *)(m_final_test + i), pattern2, sizeof(pattern2))) {
                break;
            }
        }
        if(1000 == i) {
            DbgPrint("[iemu] pattern for _issignal_locked not found, brace yourselves for a panic.\n");
            return false;
        } else {
            DbgPrint("[iemu] _issignal_locked p point found: %llx\n", m_final_test + i);
        }
        
        m_final_test += i;
        *patch = 0xE9;
        *(uint32_t *)(patch + 1) = (uint32_t)
            ((mach_vm_address_t)shellcode - (m_final_test) - 5);
        
        disable_interrupts();
        disable_wp();
        
        *(uint64_t *)(shellcode + 16) = m_final_test + 6;
        //memcpy((void *)(m_final_test), patch, sizeof(patch));
        
        enable_wp();
        enable_interrupts();
        */
        return true;
    }
    
    bool unpatch_load_macho()
    {
        /*
        if(m_load_machfile_addr) {
            disable_interrupts();
            disable_wp();
        
            memcpy((void *)m_load_machfile_addr, m_load_machfile_bytes, sizeof(m_load_machfile_bytes));
        
            enable_wp();
            enable_interrupts();
        }*/
        if(m_execsw_addr) {
            disable_interrupts();
            ((struct execsw *)m_execsw_addr)->ex_imgact = g_pfnexec_mach_imgact;
            
            /* here seals the patch of exception pass.*/
            disable_wp();
            //memcpy((void *)m_exception_triage_hook, m_exception_triage_backup, sizeof(m_exception_triage_backup));
            
            //*/
            
            //*(unsigned char *)(m_final_test) = 0x0F;
            //*(unsigned char *)(m_final_test + 1) = 0x85;
            //unsigned char copy[] = { 0x81, 0xF9, 0, 4, 0, 0 };
            //memcpy((void *)m_final_test, copy, sizeof(copy));
            
            enable_wp();
            enable_interrupts();
        }
        
        return true;
    }
    
    bool init_kernel_info()
    {
        kern_return_t error = 0;
        // lookup vnode for /mach_kernel
        vnode_t kernel_vnode = NULLVP;
        error = vnode_lookup(MACH_KERNEL, 0, &kernel_vnode, NULL);
        if (error) return false;
        
        void *kernel_header = IOMalloc(PAGE_SIZE_64);
        if (kernel_header == NULL) return false;
        
        // read and process kernel header from filesystem
        if(!get_kernel_mach_header(kernel_header, kernel_vnode)) goto failure;
        if(!process_kernel_mach_header(kernel_header, &m_kernel_info)) goto failure;
        
        // compute kaslr slide
        get_running_text_address(&m_kernel_info);
        m_kernel_info.kaslr_slide = m_kernel_info.running_text_addr - m_kernel_info.disk_text_addr;
        
        DbgPrint("[iemu]  kernel aslr slide is 0x%llx\n", m_kernel_info.kaslr_slide);
        // we know the location of linkedit and offsets into symbols and their strings
        // now we need to read linkedit into a buffer so we can process it later
        // __LINKEDIT total size is around 1MB
        // we should free this buffer later when we don't need anymore to solve symbols
        m_kernel_info.linkedit_buf = IOMalloc(m_kernel_info.linkedit_size);
        if (m_kernel_info.linkedit_buf == NULL) {
            IOFree(kernel_header, m_kernel_info.linkedit_size);
            return false;
        }
        // read linkedit from filesystem
        error = get_kernel_linkedit(kernel_vnode, &m_kernel_info);
        if (error) goto failure;
        
    success:
        DbgPrint("[iemu] success...\n");
        IOFree(kernel_header, PAGE_SIZE_64);
        DbgPrint("[iemu] after IOFree...\n");
        // drop the iocount due to vnode_lookup()
        // we must do this else machine will block on shutdown/reboot
        vnode_put(kernel_vnode);
        DbgPrint("[iemu] after vnode_put...\n");
        return true;
        
    failure:
        DbgPrint("[iemu] failure...\n");
        if (m_kernel_info.linkedit_buf != NULL) IOFree(m_kernel_info.linkedit_buf, m_kernel_info.linkedit_size);
        IOFree(kernel_header, PAGE_SIZE_64);
        vnode_put(kernel_vnode);
        return false;
    }
    
    /*
     * cleanup the kernel info buffer to avoid memory leak.
     * there's nothing else to cleanup here, for now
     */
    bool
    cleanup_kernel_info()
    {
        if (m_kernel_info.linkedit_buf != NULL) IOFree(m_kernel_info.linkedit_buf, m_kernel_info.linkedit_size);
        return true;
    }
    
    /*
     * retrieve the first page of kernel binary at disk into a buffer
     * version that uses KPI VFS functions and a ripped uio_createwithbuffer() from XNU
     */
    bool
    get_kernel_mach_header(void *buffer, vnode_t kernel_vnode)
    {
        int error = 0;
        
        uio_t uio = NULL;
        uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
        if (uio == NULL) goto __out;
        // imitate the kernel and read a single page from the header
        error = uio_addiov(uio, CAST_USER_ADDR_T(buffer), PAGE_SIZE_64);
        if (error) goto __out;
        // read kernel vnode into the buffer
        error = VNOP_READ(kernel_vnode, uio, 0, NULL);
        
        if (error) goto __out;
        else if (uio_resid(uio)) goto __out;
        
        uio_free(uio);
        return true;
    __out:
        if(uio)
            uio_free(uio);
        return false;
    }
    
    /*
     * retrieve necessary mach-o header information from the kernel buffer
     * stored at our kernel_info structure
     */
    bool
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
    void
    get_running_text_address(struct kernel_info *kinfo)
    {
        // retrieves the address of the IDT
        mach_vm_address_t idt_address = 0;
        get_addr_idt(&idt_address);
        // calculate the address of the int80 handler
        mach_vm_address_t int80_address = calculate_int80address(idt_address);
        // search backwards for the kernel base address (mach-o header)
        mach_vm_address_t kernel_base = find_kernel_base(int80_address);
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
     * retrieve the whole linkedit segment into target buffer from kernel binary at disk
     * we keep this buffer until we don't need to solve symbols anymore
     */
    kern_return_t
    get_kernel_linkedit(vnode_t kernel_vnode, struct kernel_info *kinfo)
    {
        int error = 0;
        uio_t uio = NULL;
        //    char uio_buf[UIO_SIZEOF(1)];
        //    uio = uio_createwithbuffer(1, kinfo->linkedit_fileoff, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
        uio = uio_create(1, kinfo->linkedit_fileoff, UIO_SYSSPACE, UIO_READ);
        if (uio == NULL) return KERN_FAILURE;
        error = uio_addiov(uio, CAST_USER_ADDR_T(kinfo->linkedit_buf), kinfo->linkedit_size);
        if (error) return error;
        error = VNOP_READ(kernel_vnode, uio, 0, NULL);
        
        if (error) return error;
        else if (uio_resid(uio)) return EINVAL;
        
        return KERN_SUCCESS;
    }

    /*
     * calculate the address of the kernel int80 handler
     * using the IDT array
     */
    mach_vm_address_t
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
        DbgPrint("[iemu]  Address of interrupt 80 stub is %llx\n", int80_address);

        return int80_address;
    }
    
    /*
     * find the kernel base address (mach-o header)
     * by searching backwards using the int80 handler as starting point
     */
    mach_vm_address_t
    find_kernel_base(const mach_vm_address_t int80_address)
    {
        mach_vm_address_t temp_address = int80_address;
        struct segment_command_64 *segment_command = NULL;
        
        while (temp_address > 0) {
            if (*(uint32_t*)(temp_address) == MH_MAGIC_64 && ((struct mach_header_64*)temp_address)->filetype == MH_EXECUTE) {
                // make sure it's the header and not some reference to the MAGIC number
                segment_command = (struct segment_command_64*)(temp_address + sizeof(struct mach_header_64));
                if (strncmp(segment_command->segname, "__TEXT", 16) == 0) {
                    DbgPrint("[iemu]  Found running kernel mach-o header address at %p\n", (void*)(temp_address));
                    return temp_address;
                }
            }
            // check for int overflow
            if (temp_address - 1 > temp_address) break;
            temp_address--;
        }
        return 0;
    }
    
    /*
     * function to solve a kernel symbol
     */
    mach_vm_address_t
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
    struct kernel_info m_kernel_info;
    //unsigned char m_load_machfile_bytes[5];
    //mach_vm_address_t m_load_machfile_addr;
    mach_vm_address_t m_execsw_addr;
    
    uint8_t m_exception_triage_backup[5];
    mach_vm_address_t m_exception_triage_hook;
    
    mach_vm_address_t m_final_test;
};
