
#include "iemukern.h"
#include "MachOLocator.h"
#include <IOKit/IOLib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include "log.h"
#include "iemukern.h"
#include "exports.h"
#include "vfs.h"

InMemoryMachO *findKextByName(const char *name)
{
    extern kmod_info_t kmod_info;
    kmod_info_t *next_kmod_info = &kmod_info;
    InMemoryMachO *ret = nullptr;
    
    do {
        DbgPrint("[iemu] kext name: %s is loaded at %lu", next_kmod_info->name, next_kmod_info->address);
        if(!strcmp(next_kmod_info->name, name)) {
            break;
        }
    } while((next_kmod_info = next_kmod_info->next));
    
    if(next_kmod_info) {
        // Found.
        ret = InMemoryMachO::createInMemoryMachO((const struct mach_header *)next_kmod_info->address);
    }
    
    return ret;
}

typedef kern_return_t (*fn_task_info)
(
    task_name_t target_task,
    task_flavor_t flavor,
    task_info_t task_info_out,
    mach_msg_type_number_t *task_info_outCnt
);
static fn_task_info g_fntask_info = nullptr;

#define DYLD_PATH       "/usr/lib/dyld"

struct fra_param {
    vnode_t file;
    bool bit64;
    off_t offset;
    int depth;
    void *dyld_header;
};

static struct mach_header *findRightArch(struct fra_param *fra_param)
{
    int error = 0;
    
    if(fra_param->depth > 3) {
        DbgPrint("[iemu] We are going too deep into the rabbit hole, quit.\n");
        return nullptr;
    }
    
    if (fra_param->dyld_header == nullptr) {
        DbgPrint("[iemu] No buffer is provided to %s.\n", __FUNCTION__);
        return nullptr;
    }
    
    error = vfs_read_file(fra_param->dyld_header, fra_param->file, fra_param->offset, PAGE_SIZE_64 * 2, vfs_context_current());
    if(error) {
        DbgPrint("[iemu] Cannot read dyld file.\n");
        return nullptr;
    }
    
    switch(*(uint32_t *)fra_param->dyld_header) {
        case FAT_CIGAM:
        case FAT_MAGIC:
        {
            // find the right one to recurse
            int nfat_arch = 0, f = 0;
            struct fat_header *fat_header = (struct fat_header *)fra_param->dyld_header;
            nfat_arch = OSSwapBigToHostInt32(fat_header->nfat_arch);
            struct fat_arch *arches = (struct fat_arch *)(fat_header + 1);
            
            for(f = 0; f < nfat_arch; f ++) {
                
                cpu_type_t archtype = OSSwapBigToHostInt32(arches[f].cputype);
                if((archtype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64) {
                    if(fra_param->bit64) {
                        fra_param->depth ++;
                        fra_param->offset = OSSwapBigToHostInt32(arches[f].offset);
                        return findRightArch(fra_param);
                    }
                } else {
                    if(!fra_param->bit64) {
                        fra_param->depth ++;
                        fra_param->offset = OSSwapBigToHostInt32(arches[f].offset);
                        return findRightArch(fra_param);
                    }
                }
            }
            
            // no arch is the right arch
            return nullptr;
        }
        case MH_MAGIC:
            if(fra_param->bit64) {
                return nullptr;
            }
            
            
            return (struct mach_header *)fra_param->dyld_header;
        case MH_MAGIC_64:
            if(!fra_param->bit64) {
                return nullptr;
            }
            
            return (struct mach_header *)fra_param->dyld_header;
        default:
            return nullptr;
    }
}

static uintptr_t findDyldBaseByAllImageInfos(uintptr_t allImageInfos_addr, bool bit64)
{
    //
    // It's time to read dyld from disk.
    kern_return_t error = 0;
    struct mach_header *mach_header = nullptr;
    uint32_t header_size;
    struct fra_param fra_param = {};
    struct load_command *load_cmd = nullptr;
    char *load_cmd_addr = nullptr;
    uint64_t dyld_text_vmaddr = 0, dyld_all_image_infos_vmaddr = 0;
    
    vnode_t dyld_vnode = NULLVP;
    error = vnode_lookup(DYLD_PATH, 0, &dyld_vnode, vfs_context_current());
    if (error) {
        DbgPrint("[iemu] error vnode_lookup: %s, %d\n", DYLD_PATH, error);
        return 0;
    }
    
    fra_param.file = dyld_vnode;
    fra_param.offset = 0;
    fra_param.depth = 0;
    fra_param.bit64 = bit64;
    fra_param.dyld_header = IOMalloc(PAGE_SIZE_64 * 2);
    if(NULL == fra_param.dyld_header) {
        DbgPrint("[iemu] error in allocating dyld_header.\n");
        goto failure;
    }
    
    mach_header = findRightArch(&fra_param);
    if(nullptr == mach_header) {
        DbgPrint("[iemu] Cannot find the right architecture for dyld.\n");
        goto failure;
    }
    
    header_size = bit64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    load_cmd_addr = (char*)mach_header + header_size;
    
    for (uint32_t i = 0; i < mach_header->ncmds; i++) {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            if (strncmp(seg_cmd->segname, "__TEXT", 7) == 0) {
                dyld_text_vmaddr = seg_cmd->vmaddr;
            } else if(strncmp(seg_cmd->segname, "__DATA", 7) == 0) {
                struct section_64 *section = (struct section_64 *)(seg_cmd + 1);
                for(uint32_t j = 0; j < seg_cmd->nsects; j ++) {
                    if(strncmp(section[j].sectname, "__all_image_info", 16) == 0) {
                        dyld_all_image_infos_vmaddr = section[j].addr;
                    }
                }
            }
        } else if(load_cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg_cmd = (struct segment_command*)load_cmd;
            if (strncmp(seg_cmd->segname, "__TEXT", 7) == 0) {
                dyld_text_vmaddr = seg_cmd->vmaddr;
            } else if(strncmp(seg_cmd->segname, "__DATA", 7) == 0) {
                struct section *section = (struct section *)(seg_cmd + 1);
                for(uint32_t j = 0; j < seg_cmd->nsects; j ++) {
                    if(strncmp(section[j].sectname, "__all_image_info", 16) == 0) {
                        dyld_all_image_infos_vmaddr = section[j].addr;
                    }
                }
            }
        }
        load_cmd_addr += load_cmd->cmdsize;
    }
    
    if(dyld_all_image_infos_vmaddr == 0) {
        DbgPrint("[iemu] Cannot find section __all_image_info.\n");
        goto failure;
    }
    
    IOFree(fra_param.dyld_header, PAGE_SIZE_64 * 2);
    vnode_put(dyld_vnode);
    return allImageInfos_addr - (dyld_all_image_infos_vmaddr - dyld_text_vmaddr);
failure:
    if(fra_param.dyld_header)
        IOFree(fra_param.dyld_header, PAGE_SIZE_64 * 2);
    vnode_put(dyld_vnode);
    return 0;
}

InMemoryMachO *findDyldInUser(bool bit64, task_t task)
{
    task_dyld_info_data_t tdi;
    mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
    
    if(nullptr == g_fntask_info)
        g_fntask_info = (fn_task_info)com_cod_iemukern::solve_kernel_symbol("_task_info");
    
    kern_return_t kern_ret = g_fntask_info(task, TASK_DYLD_INFO, (task_info_t)&tdi, &task_info_outCnt);
    if(kern_ret != KERN_SUCCESS) {
        DbgPrint("[iemu] task_info failed");
        return nullptr;
    } else {
        InMemoryMachO *ret = nullptr;

        DbgPrint("[iemu] dyld info, addr: 0x%llx, size: 0x%llx, format: %d",
                 tdi.all_image_info_addr, tdi.all_image_info_size, tdi.all_image_info_format);
        
        uintptr_t dyld_base = findDyldBaseByAllImageInfos(tdi.all_image_info_addr, bit64);
        DbgPrint("[iemu] dyld_base: 0x%lx.\n", dyld_base);
        
        vm_map_t old_map = my_vm_map_switch(my_get_task_map(task));
        
        ret = InMemoryMachO::createInMemoryMachO((const struct mach_header *)dyld_base, true);
        
        my_vm_map_switch(old_map);
        
        return ret;
    }
}
