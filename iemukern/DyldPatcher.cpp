#include "iemukern.h"
#include "MachOLocator.h"
#include "DyldPatcher.h"
#include "log.h"
#include "exports.h"

extern "C"
void patchDyld(bool bit64, task_t task)
{
    static uint8_t my_fatFindBest32[] = {
                                    // clang fastcall protocol
                                    // ecx      = const fat_header *fh
                                    // edx      = uint64_t *offset
                                    // [esp+4]  = uint64_t *len
        0x33, 0xC0,                 // xor eax, eax
        0x89, 0x42, 0x04,           // mov dword ptr [edx+4], eax   // set hi of offset to 0
        0x52,                       // push edx
        0x8B, 0x54, 0x24, 0x08,     // mov edx, dword ptr [esp+8]
        0x89, 0x42, 0x04,           // mov dword ptr [edx+4], eax   // set hi of len to 0
        0x5A,                       // pop edx
        
        0x60,                       // pusha
        0x8B, 0x51, 0x04,           // mov edx, dword ptr [ecx+4]   // fh->nfat_arch
        0x0F, 0xCA,                 // bswap edx
        0x83, 0xC1, 0x08,           // add ecx, 8                   // fat_arch *fa
// start:
        0x85, 0xD2,                 // test edx, edx
        0x74, 0x36,                 // jz end
        0x8B, 0x31,                 // mov esi, dword ptr [ecx]     // fa->cpu_type
        0x0F, 0xCE,                 // bswap esi
        0x83, 0xFE, 0x07,           // cmp esi, 7                   // 7 = CPU_TYPE_X86
        0x74, 0x05,                 // jz next
        0x83, 0xFE, 0x0C,           // cmp esi, 0x0C                // 0xC = CPU_TYPE_ARM
        0x75, 0x22,                 // jnz next2
// next:
        0x8B, 0x79, 0x08,           // mov edi dword ptr [ecx+8]    // fa->offset
        0x0F, 0xCF,                 // bswap edi
        0x8B, 0x5C, 0x24, 0x14,     // mov ebx, dword ptr [esp+0x14]// where edx is after pusha
        0x89, 0x3B,                 // mov dword ptr [ebx], edi
        0x8B, 0x79, 0x0C,           // mov edi, dword ptr [ecx+0xC] // fa->len
        0x0F, 0xCF,                 // bswap edi
        0x8B, 0x5C, 0x24, 0x24,     // mov ebx, dword ptr [esp+0x24]// esp+4
        0x89, 0x3B,                 // mov dword ptr [ebx], edi
        0x33, 0xC0,                 // xor eax, eax
        0x40,                       // inc eax
        0x89, 0x44, 0x24, 0x1C,     // mov dword ptr [esp+0x1C], eax// set eax to after popa
        0x83, 0xFE, 0x07,           // cmp esi, 7
        0x74, 0x06,                 // jz end
// next2:
        0x83, 0xC1, 0x14,           // add ecx, 0x14
        0x4A,                       // dec edx
        0xEB, 0xC6,                 // jmp start
// end:
        0x61,                       // popa
        0xC3                        // retn
        
    };
    static uint8_t my_fatFindBest64[] = {
        0x53,                       // push rbx
        0x4D, 0x33, 0xC0,           // xor r8, r8
        0x8B, 0x4F, 0x04,           // mov ecx, dword ptr [rdi+4]
        0x0F, 0xC9,                 // bswap ecx
        0x48, 0x83, 0xC7, 0x08,     // add rdi, 8
// start:
        0x85, 0xC9,                 // test ecx, ecx
        0x74, 0x35,                 // jz end
        0x8B, 0x07,                 // mov eax, dword ptr [rdi]
        0x3D, 1, 0, 0, 7,           // cmp eax, 0x7000001
        0x74, 0x07,                 // jz next
        0x3D, 1, 0, 0, 0x0C,        // cmp eax, 0xC000001
        0x75, 0x1D,                 // jnz next2
// next:
        0x8B, 0x5F, 0x08,           // mov ebx, dword ptr [rdi+8]
        0x0F, 0xCB,                 // bswap ebx
        0x48, 0x89, 0x1E,           // mov qword ptr [rsi], rbx
        0x8B, 0x5F, 0x0C,           // mov ebx, dword ptr [rdi+0x0C]
        0x0F, 0xCB,                 // bswap ebx
        0x48, 0x89, 0x1A,           // mov qword ptr [rdx], rbx
        0x41, 0xB8, 1, 0, 0, 0,     // mov r8d, 1
        0x3D, 1, 0, 0, 7,           // cmp eax, 0x7000001
        0x74, 0x08,                 // je end
// next2:
        0x48, 0x83, 0xC7, 0x14,     // add, rdi, 0x14
        0xFF, 0xC9,                 // dec ecx
        0xEB, 0xC7,                 // jmp start
// end:
        0x41, 0x8B, 0xC0,           // mov eax, r8d
        0x5B,                       // pop rbx
        0xC3                        // retn
    };
    
    static uint8_t my_isCompatibleMachO[] = {
        0x33, 0xC0,                 // xor eax, eax
        0xFF, 0xC0,                 // inc eax
        0xC3                        // retn
    };
    
    InMemoryMachO *ret = findDyldInUser(bit64, task);
    if(ret) {
        char *rewrite;
        vm_map_t target_map = my_get_task_map(task);
        vm_map_t old_map = my_vm_map_switch(target_map);
        kern_return_t kern;
        
        mach_vm_address_t fatFindBest = ret->solveSymbol("__ZN4dyldL11fatFindBestEPK10fat_headerPyS3_");
        DbgPrint("[iemu] dyld fatFindBest: 0x%llx.\n", fatFindBest);
        mach_vm_address_t isCompatibleMachO = 0;
        
        if(bit64) {
            isCompatibleMachO = ret->solveSymbol("__ZN4dyld17isCompatibleMachOEPKhPKc");
            DbgPrint("[iemu] dyld isCompatibleMachO: 0x%llx.\n", isCompatibleMachO);
        }
        
        kern = vm_protect(target_map,
                          fatFindBest,
                          bit64 ? sizeof(my_fatFindBest64) : sizeof(my_fatFindBest32),
                          false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
        if(kern != KERN_SUCCESS) {
            DbgPrint("[iemu] vm_protect failed with %d.\n", kern);
            goto __exit0;
        }
        if(bit64) {
            kern = vm_protect(target_map, isCompatibleMachO, sizeof(my_isCompatibleMachO), false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
            
            if(kern != KERN_SUCCESS) {
                DbgPrint("[iemu] vm_protect failed with %d #1.\n", kern);
                goto __exit0;
            }
        }
        
        //disable_interrupts();
        disable_smap();
        
        // Patch the fatFindBest function.
        memcpy((void *)fatFindBest, bit64 ? my_fatFindBest64 : my_fatFindBest32,
               bit64 ? sizeof(my_fatFindBest64) : sizeof(my_fatFindBest32));
        
        // Patch the isCompatibleMachO function.
        if(bit64) {
            memcpy((void *)isCompatibleMachO, my_isCompatibleMachO, sizeof(my_isCompatibleMachO));
        }
        
        enable_smap();
        //enable_interrupts();
        
        kern = vm_protect(target_map,
                          fatFindBest,
                          bit64 ? sizeof(my_fatFindBest64) : sizeof(my_fatFindBest32),
                          false, VM_PROT_READ | VM_PROT_EXECUTE);
        
        if(bit64) {
            kern = vm_protect(target_map,
                          isCompatibleMachO,
                          sizeof(my_isCompatibleMachO),
                          false, VM_PROT_READ | VM_PROT_EXECUTE);
        }
        
        rewrite = (char *)ret->findCString("__RESTRICT");
        kern = vm_protect(target_map, (vm_address_t)rewrite, 11, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
        if(kern != KERN_SUCCESS) {
            DbgPrint("[iemu] vm_protect failed with %d #2.\n", kern);
            goto __exit0;
        }
        
        //disable_interrupts();
        disable_smap();
        strlcpy(rewrite, "xxRESTRICT", 11);
        enable_smap();
        //enable_interrupts();
        
        kern = vm_protect(target_map, (vm_address_t)rewrite, 11, false, VM_PROT_READ | VM_PROT_EXECUTE);
        
        rewrite = (char *)ret->findCString("__restrict");
        kern = vm_protect(target_map, (vm_address_t)rewrite, 11, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
        if(kern != KERN_SUCCESS) {
            DbgPrint("[iemu] vm_protect failed with %d #3.\n", kern);
            goto __exit0;
        }
        
        //disable_interrupts();
        disable_smap();
        strlcpy(rewrite, "xxrestrict", 11);
        enable_smap();
        //enable_interrupts();
        
        kern = vm_protect(target_map, (vm_address_t)rewrite, 11, false, VM_PROT_READ | VM_PROT_EXECUTE);
        
    __exit0:
        my_vm_map_switch(old_map);
        delete ret;
    }
}
