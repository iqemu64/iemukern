
#ifndef InMemoryMachO_h
#define InMemoryMachO_h

#include <sys/types.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include "cpu_protection.h"
#include "log.h"


class InMemoryMachO {
private:
    class AutoEnableSMAP {
    public:
        AutoEnableSMAP() {}
        ~AutoEnableSMAP() {
            enable_smap();
            //enable_interrupts();
        }
    };
public:
#define DISABLE_SMAP(x) do {    \
                            if(x) { \
                                disable_smap();         \
                            }   \
                        } while(0)
#define ENABLE_SMAP(x)  do {    \
                            if(x) { \
                                enable_smap();  \
                            }   \
                        } while(0)
    static InMemoryMachO *createInMemoryMachO(const struct mach_header *header, bool in_userspace = false)
    {
        AutoEnableSMAP _aes;
        bool bit64;
        uint32_t header_size;
        
        DISABLE_SMAP(in_userspace);
        if(header->magic == MH_MAGIC_64) {
            bit64 = true;
            header_size = sizeof(struct mach_header_64);
        } else if(header->magic == MH_MAGIC) {
            bit64 = false;
            header_size = sizeof(struct mach_header);
        } else {
            DbgPrint("[iemu] This is an invalid mach header");
            return nullptr;
        }
        
        InMemoryMachO *ret = new InMemoryMachO();
        ret->m_bit64 = bit64;
        ret->m_base = (mach_vm_address_t)header;
        ret->m_in_userspace = in_userspace;
        
        char *load_cmd_addr = (char*)header + header_size;
        
        DISABLE_SMAP(in_userspace);
        for (uint32_t i = 0; i < header->ncmds; i++) {
            struct load_command *load_cmd = (struct load_command *)load_cmd_addr;

            if (load_cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
                if (strncmp(seg_cmd->segname, "__TEXT", 7) == 0) {
                    ret->m_text_addr = seg_cmd->vmaddr;
                    ret->m_text_size = seg_cmd->vmsize;
                    ret->m_aslr = (mach_vm_address_t)header - seg_cmd->vmaddr;
                    struct section_64 *section = (struct section_64 *)(seg_cmd + 1);
                    for(uint32_t j = 0; j < seg_cmd->nsects; j ++) {
                        if(strncmp(section[j].sectname, "__cstring", 10) == 0) {
                            ret->m_cstring_addr = section[j].addr;
                            ret->m_cstring_size = section[j].size;
                            break;
                        }
                    }
                } else if(strncmp(seg_cmd->segname, "__LINKEDIT", 11) == 0) {
                    ret->m_linkedit_addr = seg_cmd->vmaddr + ret->m_aslr;
                    ret->m_linkedit_size = seg_cmd->vmsize;
                    ret->m_linkedit_fileoff     = seg_cmd->fileoff;
                    ret->m_linkedit_filesize    = seg_cmd->filesize;
                }
            } else if(load_cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg_cmd = (struct segment_command*)load_cmd;
                if (strncmp(seg_cmd->segname, "__TEXT", 7) == 0) {
                    ret->m_text_addr = seg_cmd->vmaddr;
                    ret->m_text_size = seg_cmd->vmsize;
                    ret->m_aslr = (mach_vm_address_t)header - seg_cmd->vmaddr;
                    struct section *section = (struct section *)(seg_cmd + 1);
                    for(uint32_t j = 0; j < seg_cmd->nsects; j ++) {
                        if(strncmp(section[j].sectname, "__cstring", 10) == 0) {
                            ret->m_cstring_addr = section[j].addr;
                            ret->m_cstring_size = section[j].size;
                            break;
                        }
                    }
                } else if(strncmp(seg_cmd->segname, "__LINKEDIT", 11) == 0) {
                    ret->m_linkedit_addr = seg_cmd->vmaddr + ret->m_aslr;
                    ret->m_linkedit_size = seg_cmd->vmsize;
                    ret->m_linkedit_fileoff     = seg_cmd->fileoff;
                    ret->m_linkedit_filesize    = seg_cmd->filesize;
                }
            } else if(load_cmd->cmd == LC_SYMTAB) {
                struct symtab_command *symtab_cmd = (struct symtab_command*)load_cmd;
                ret->m_symboltable_fileoff      = symtab_cmd->symoff;
                ret->m_symboltable_nr_symbols   = symtab_cmd->nsyms;
                ret->m_stringtable_fileoff      = symtab_cmd->stroff;
                ret->m_stringtable_size         = symtab_cmd->strsize;
            }
            load_cmd_addr += load_cmd->cmdsize;
        }
        
        return ret;
    }
    
    void debugPrintAllParameters()
    {
        DbgPrint("[iemu] m_text_addr: %llx\n", m_text_addr);
        DbgPrint("[iemu] m_text_size: %llx\n", m_text_size);
        DbgPrint("[iemu] m_aslr: %llx\n", m_aslr);
        DbgPrint("[iemu] m_linkedit_addr: %llx\n", m_linkedit_addr);
        DbgPrint("[iemu] m_linkedit_size: %llx\n", m_linkedit_size);
    }
    
    ~InMemoryMachO() {}
    
    mach_vm_address_t findCString(const char *cstring)
    {
        char *real_cstring_addr;
        uint64_t section_current = 0;
        
        if(0 == m_cstring_addr) {
            DbgPrint("[iemu] cstring segement hasn't been found yet.\n");
            return 0;
        }
        if(nullptr == cstring) return 0;
        
        AutoEnableSMAP _aes;
        DISABLE_SMAP(m_in_userspace);
        
        real_cstring_addr = (char *)m_cstring_addr + m_aslr;
        
        // compare string...
        uint64_t str_current = 0;
        
        while(section_current < m_cstring_size) {
            while(real_cstring_addr[section_current] == cstring[str_current]) {
                if(cstring[str_current] == '\0') {
                    mach_vm_address_t ret = (mach_vm_address_t)real_cstring_addr + section_current - strlen(cstring);
                    DbgPrint("[iemu] We found string: %s.\n", (const char *)ret);
                    return ret;
                }
                section_current ++;
                str_current ++;
            }
            // advance until \0 is met in the section
            str_current = 0;
            while(real_cstring_addr[section_current++] != '\0');
        }
        return 0;
    }
    
    mach_vm_address_t solveSymbol(const char *symbol_to_solve)
    {
        struct nlist_64 *nlist = NULL;
        uint32_t nlist_size = m_bit64 ? sizeof(struct nlist_64) : sizeof(struct nlist);
        
        if (m_linkedit_addr == 0) return 0;
        AutoEnableSMAP _aes;
        
        // symbols and strings offsets into LINKEDIT
        // we just read the __LINKEDIT but fileoff values are relative to the full /mach_kernel
        // subtract the base of LINKEDIT to fix the value into our buffer
        mach_vm_address_t symbol_off = m_symboltable_fileoff - m_linkedit_fileoff;
        mach_vm_address_t string_off = m_stringtable_fileoff - m_linkedit_fileoff;
        // search for the symbol and get its location if found
        DISABLE_SMAP(m_in_userspace);
        for (uint32_t i = 0; i < m_symboltable_nr_symbols; i++) {
            // get the pointer to the symbol entry and extract its symbol string
            nlist = (struct nlist_64*)((char*)m_linkedit_addr + symbol_off + i * nlist_size);
            char *symbol_string = ((char*)m_linkedit_addr + string_off + nlist->n_un.n_strx);
            // find if symbol matches
            // XXX: we could obfuscate this and make it faster with some hash algo
            if (strncmp(symbol_to_solve, symbol_string, strlen(symbol_to_solve)) == 0 &&
                (nlist->n_type & N_STAB) == 0) {
                if(m_bit64) {
                    DbgPrint("[iemu] found symbol %s at 0x%llx\n", symbol_to_solve, nlist->n_value);
                    return nlist->n_value + m_aslr;
                } else {
                    // 32bit macho
                    struct nlist *nlist_32 = (struct nlist *)nlist;
                    DbgPrint("[iemu] found symbol %s at 0x%x\n", symbol_to_solve, nlist_32->n_value);
                    return nlist_32->n_value + m_aslr;
                    
                }
            }
        }
        // failure
        return 0;
    }
    
private:
    InMemoryMachO()
        :  m_base(0),
        m_aslr(0),
        m_text_addr(0),
        m_text_size(0),
        m_linkedit_addr(0),
        m_linkedit_size(0),
        m_linkedit_fileoff(0),
        m_linkedit_filesize(0),
        m_cstring_addr(0),
        m_cstring_size(0),
        m_symboltable_fileoff(0),
        m_symboltable_nr_symbols(0),
        m_stringtable_fileoff(0),
        m_stringtable_size(0),
        m_bit64(false),
        m_in_userspace(false)
    {
        //
    }
    
    mach_vm_address_t   m_base;
    mach_vm_address_t   m_aslr;
    mach_vm_address_t   m_text_addr;
    uint64_t            m_text_size;
    mach_vm_address_t   m_linkedit_addr;
    uint64_t            m_linkedit_size;
    uint64_t            m_linkedit_fileoff;
    uint64_t            m_linkedit_filesize;
    uint64_t            m_cstring_addr;
    uint64_t            m_cstring_size;
    
    uint32_t            m_symboltable_fileoff;
    uint32_t            m_symboltable_nr_symbols;
    uint32_t            m_stringtable_fileoff;
    uint32_t            m_stringtable_size;
    bool                m_bit64;
    bool                m_in_userspace;
};

#endif /* InMemoryMachO_h */
