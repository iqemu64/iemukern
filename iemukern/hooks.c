
#include <IOKit/IOLib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/fcntl.h>
#include <libkern/libkern.h>

#include "hooks.h"
#include "thread_state.h"
#include "log.h"

ex_imgact g_pfnexec_mach_imgact = NULL;

static fn_current_map g_pfncurrent_map = NULL;
static fn_exception_deliver g_pfnexception_deliver = NULL;
static fn_thread_adjuserstack g_pfnthread_adjuserstack = NULL;

#define CPU_TYPE_ARM64  (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define ENV_DYLD_INSERT_LIBRARIES   "DYLD_INSERT_LIBRARIES="
#define IEMU_USER_DYLIB             "/usr/local/lib/libiqemu.dylib"
#define ENV_DYLD_LIBRARY_PATH       "DYLD_LIBRARY_PATH="
#define IEMU_LIBRARY_PATH           "/usr/local/simulator_bin"

bool
init_hooks(struct hookp *hookp)
{
    if(NULL == hookp->current_map || NULL == hookp->real_exception_deliver) {
        return false;
    }
    
    g_pfncurrent_map = hookp->current_map;
    g_pfnexception_deliver = hookp->real_exception_deliver;
    g_pfnthread_adjuserstack = hookp->thread_adjuserstack;
    return true;
}

//
// This function is exported by kernel but limited to
// private framework, to which we cannot link. Ain't get
// no clue on why.
char *
strnstr(char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;
    
    if((c = *find ++) != '\0') {
        len = strlen(find);
        do {
            do {
                if((sc = *s++) == '\0' || slen -- < 1)
                    return (NULL);
            } while(sc != c);
            if(len > slen)
                return (NULL);
        } while(strncmp(s, find, len) != 0);
        s --;
    }
    return (s);
}


static int
copyinptr(user_addr_t froma, user_addr_t *toptr, int ptr_size)
{
    int error;
    if(ptr_size == 4) {
        unsigned int i;
        
        error = copyin(froma, &i, 4);
        *toptr = CAST_USER_ADDR_T(i);
    } else {
        error = copyin(froma, toptr, 8);
    }
    
    return (error);
}

static int
copyoutptr(user_addr_t ua, user_addr_t ptr, int ptr_size)
{
    int error;
    if(ptr_size == 4) {
        unsigned int i = CAST_DOWN_EXPLICIT(unsigned int, ua);
        error = copyout(&i, ptr, 4);
    } else {
        error = copyout(&ua, ptr, 8);
    }
    return (error);
}

static int
copyoutnptr(user_addr_t ua, user_addr_t ptr, int ptr_size, size_t left_space)
{
    if(left_space < ptr_size)
        return E2BIG;
    return copyoutptr(ua, ptr, ptr_size);
}

static int
copyoutnstr(const void *kaddr, user_addr_t udaddr, size_t len, size_t *done, size_t left_space)
{
    if(left_space <= len)
        return E2BIG;
    return copyoutstr(kaddr, udaddr, len, done);
}

/*
 * copy all the original environment variables
 * to the addr specified user address and reside
 * them with the new key/value environment.
 * returns the size used from the end of the user
 * page.
 */

static size_t
add_environment(struct image_params *imgp,
                 user_addr_t addr,
                 size_t usize,
                 const char *key,
                 const char *value)
{
    user_addr_t env;
    int ptr_size = (imgp->ip_flags & IMGPF_WAS_64BIT) ? 8 : 4;
    user_addr_t envv = imgp->ip_user_envv;
    size_t len = 0;
    const size_t envlen  = strlen(key);
    void *str = NULL;
    bool extra_env = true;
    size_t ret = 0;
    
    vm_address_t cur_addr = addr;
    size_t space = usize;
    int error = 0;
    
    str = IOMalloc(page_size);
    
    DbgPrint("[iemu] begin env dump.\n");
    while (envv != 0LL) {
        //DbgPrint("[iemu] envv = 0x%llx.\n", envv);
        error = copyinptr(envv, &env, ptr_size);
        if(error)
            goto bad;
        if(env == 0LL) {
            break;
        }
        
        error = copyinstr(env, str, page_size, &len);
        if(error)
            goto bad;
        DbgPrint("[iemu] env: %s\n", str);
        if(!strncmp(str, key, envlen)) {
            if(!strnstr(str, value, strlen(str))) {
                //
                // a strcat is happening...
                strlcat(str, ":", page_size);
                size_t n = strlcat(str, value, page_size);
                
                //
                // copy that to the end of the user page.
                env = addr + usize - n - 1;
                error = copyoutnstr(str, env, n + 1, &len, space);
                if(error)
                    goto bad;
                space -= len;
                ret = n + 1;
                
            }
            extra_env = false;
        }
        
        error = copyoutnptr(env, cur_addr, ptr_size, space);
        if(error)
            goto bad;
        cur_addr += ptr_size;
        space -= ptr_size;
        
        envv += ptr_size;
    }
    
    if(extra_env) {
        strlcpy(str, key, page_size);
        size_t n = strlcat(str, value, page_size);
        env = addr + usize - n - 1;
        
        error = copyoutnstr(str, env, n + 1, &len, space);
        if(error)
            goto bad;
        space -= len;
        ret = n + 1;
        
        error = copyoutnptr(env, cur_addr, ptr_size, space);
        if(error)
            goto bad;
        cur_addr += ptr_size;
        space -= ptr_size;
    }
    
    //
    // the final terminator.
    error = copyoutnptr(0, cur_addr, ptr_size, space);
    if(error)
        goto bad;
    cur_addr += ptr_size;
    space -= ptr_size;
    
    DbgPrint("[iemu] end env dump.\n");
    
    IOFree(str, page_size);
    imgp->ip_user_envv = addr;
    
    return ret;
bad:
    if(str)
        IOFree(str, page_size);
    
    DbgPrint("[iemu] add_environment fails: %d.\n", error);
    return 0;
}

static bool
reside_environments(struct image_params *imgp, user_addr_t addr, size_t usize)
{
    size_t size = usize;
    size_t ret = add_environment(imgp, addr, size, ENV_DYLD_INSERT_LIBRARIES, IEMU_USER_DYLIB);
    
    size -= ret;
    ret = add_environment(imgp, addr, size, ENV_DYLD_LIBRARY_PATH, IEMU_LIBRARY_PATH);
    
    return true;
}
/*
static void
unprotect_write(vm_address_t addr, vm_size_t size)
{
    //mach_vm_protect
}
*/

static int
fix_unixthread(struct thread_command *tc, bool bit64)
{
    if(bit64)
        return 0;   /* never seen a 64bit unixthread. maybe they don't exist at all? */
    
    x86_thread_state32_t *x8632;
    struct arm_thread_state *arm32;
    uint32_t *ts = (uint32_t *)((char *)tc + sizeof(struct thread_command));
    int total_size = tc->cmdsize - sizeof(struct thread_command);
    int hole = 0;
        
    while(total_size > 0) {
        int flavor = *ts++;
        uint32_t size = *ts++;
        
        if(ARM_THREAD_STATE != flavor) {
            DbgPrint("[iemu] flavour should be %d not %d.\n", ARM_THREAD_STATE, flavor);
            return 0;
        }
        if(size != sizeof(struct arm_thread_state) / sizeof(uint32_t)) {
            DbgPrint("[iemu] size should be %d not %d.\n", 17, size);
            return 0;
        }
        
        arm32 = (struct arm_thread_state *)IOMalloc(size * sizeof(uint32_t));
        memcpy(arm32, ts, size * sizeof(uint32_t));
        x8632 = (x86_thread_state32_t *)ts;
        memset(x8632, 0, sizeof(x86_thread_state32_t));
        
        x8632->eip = arm32->pc;
        x8632->esp = arm32->sp;
        
        *(ts - 2) = x86_THREAD_STATE32;
        *(ts - 1) = sizeof(x86_thread_state32_t) / sizeof(uint32_t);
        tc->cmdsize -= 4;
        
        IOFree(arm32, size * sizeof(uint32_t));
        
        hole += 4;
        ts += size;
        //DbgPrint("[iemu] minus happening in fix_unixthread: %d - %lu.\n", total_size, size * sizeof(uint32_t));
        total_size -= (size + 2) * sizeof(uint32_t);
        
        if(total_size > 0) {
            memcpy(ts - 1, ts, total_size);
            total_size -= 4;
            ts --;
        }
    }
    
   
    return hole;
}


static bool
fix_sections(struct section *sc, int count, bool bit64)
{
    /*
     * a __dyld section could cause entry point of main binary
     * executed before initialization routine of iqemu. change 
     * it to an other name, then our lib will link this section
     * for it. This section is unlikely to be seen in
     * nowadays binaries.
     */
    char *sectname;
    
    for(int i = 0; i < count; i ++) {
        if(bit64) {
            sectname = ((struct section_64 *)sc)->sectname;
            sc = (struct section *)(((char *)sc) + sizeof(struct section_64));
        } else {
            sectname = sc->sectname;
            sc ++;
        }
        if(!strcmp(sectname, "__dyld"))
            strlcpy(sectname, "smdyld", sizeof(sc->sectname));
    }
    
    
    return true;
}

/*
 * job list: 1. add PROT_WRITE to text segments.
 *           2. change LC_UNIXTHREAD to i386 format.
 *           3. remove LC_CODE_SIGNATURE segment.
 */

static bool
manipulate_mach_header(struct mach_header *mach_header)
{
    off_t header_sz, offset;
    size_t cmdsize;
    uint32_t ncmds;
    bool bit64;
    struct load_command *lcp;
    struct segment_command *scp;
    struct segment_command_64 *scp64;
    
    if(mach_header->magic == MH_MAGIC) {
        header_sz = sizeof(struct mach_header);
        mach_header->cputype = CPU_TYPE_I386;
        bit64 = false;
    } else if(mach_header->magic == MH_MAGIC_64) {
        header_sz = sizeof(struct mach_header_64);
        mach_header->cputype = CPU_TYPE_X86_64;
        bit64 = true;
    } else {
        DbgPrint("[iemu] mach header unrecognized.\n");
        return false;
    }
    mach_header->flags |= MH_EMULATOR;
    
    ncmds = mach_header->ncmds;
    cmdsize = mach_header->sizeofcmds;
    offset = header_sz;
    size_t hole = 0;
    
    while(ncmds --) {
        lcp = (struct load_command *)((vm_address_t)mach_header + offset);
        offset += lcp->cmdsize;
        switch(lcp->cmd) {
            case LC_SEGMENT:
                if(bit64)   /* 64bit binary contains a 32 bit segment command */
                    return false;
                    
                scp = (struct segment_command *)lcp;
                if(!strcmp(scp->segname, "__TEXT")) {
                    scp->maxprot |= VM_PROT_WRITE;
                } else if(!strcmp(scp->segname, "__RESTRICT")) {
                    scp->segname[0] = scp->segname[1] = 'x';
                }
                
                if(!fix_sections((struct section *)((char *)lcp + sizeof(struct segment_command)),
                                 (lcp->cmdsize - sizeof(struct segment_command)) / sizeof(struct section),
                                 bit64))
                    return false;
                
                break;
            case LC_SEGMENT_64:

                if(!bit64)  /* 32bit binary contains a 64 bit segment command */
                    return false;
                scp64 = (struct segment_command_64 *)lcp;
                if(!strcmp(scp64->segname, "__TEXT")) {
                    scp64->maxprot |= VM_PROT_WRITE;
                }
                
                if(!fix_sections((struct section *)((char *)lcp + sizeof(struct segment_command_64)),
                                 (lcp->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64),
                                 bit64))
                    return false;
                break;
            case LC_UNIXTHREAD: {
                int l_hole = fix_unixthread((struct thread_command *)lcp, bit64);
                if(0 == l_hole) {
                    DbgPrint("[iemu] fix_unixthread fails.\n");
                    return false;
                }
                hole = l_hole;
                break;
            }
            case LC_CODE_SIGNATURE:
                mach_header->ncmds --;
                hole = lcp->cmdsize;
                break;
            default:
                break;
        }
        if(hole) {
            offset -= hole;
            mach_header->sizeofcmds -= hole;
            cmdsize = mach_header->sizeofcmds;
            
            if(!(cmdsize - offset)) {
                break;
            }
            
            //DbgPrint("[iemu] moving from %llu to %lld, size %llu.\n", offset + hole, offset, cmdsize - offset);
            /* there requested a hole, fill it in */
            memmove((void *)      ((vm_address_t)mach_header + offset),
                    (const void *)((vm_address_t)mach_header + offset + hole),
                    cmdsize - offset + header_sz);
            hole = 0;
        }
    }
    
    return true;
}

static bool
vfs_manipulate_mach_header(struct image_params *imgp)
{
    int error = 0;
    bool ret = false;
    size_t buf_size = PAGE_SIZE_64;
    uio_t uio_read = NULL, uio_write = NULL;
    uio_read  = uio_create(1, imgp->ip_arch_offset, UIO_SYSSPACE, UIO_READ);
    if (uio_read == NULL) goto __out;
    uio_write = uio_create(1, imgp->ip_arch_offset, UIO_SYSSPACE, UIO_WRITE);
    if (uio_write == NULL) goto __out;
    
    
    char *buf = IOMalloc(buf_size);
    if(NULL == buf) goto __out;

    // read the mach_header to determine how much bytes we actuall need to read
    error = uio_addiov(uio_read, CAST_USER_ADDR_T(buf), buf_size);
    if (error) goto __out;
        
    error = VNOP_READ(imgp->ip_vp, uio_read, 0, imgp->ip_vfs_context);
    if (error) goto __out;
    
    struct mach_header *mach_header = (struct mach_header *)buf;
    
    buf_size = (mach_header->magic == MH_MAGIC) ?
        sizeof(struct mach_header) :
        sizeof(struct mach_header_64);
    buf_size += mach_header->sizeofcmds;
    
    IOFree(buf, PAGE_SIZE_64);
    
    DbgPrint("[iemu] size determined, read the whole header+load commands.\n");
    /* now that size is determined, read the whole story */
    buf = IOMalloc(buf_size);
    if(NULL == buf) goto __out;
    
    uio_reset(uio_read, imgp->ip_arch_offset, UIO_SYSSPACE, UIO_READ);
    error = uio_addiov(uio_read, CAST_USER_ADDR_T(buf), buf_size);
    if(error) goto __out;
    error = VNOP_READ(imgp->ip_vp, uio_read, 0, imgp->ip_vfs_context);
    if(error) goto __out;
    
    DbgPrint("[iemu] trying to manipulate mach header, offset=%llu.\n", imgp->ip_arch_offset);
    if(!manipulate_mach_header((struct mach_header *)buf)) goto __out;
    DbgPrint("[iemu] manipulated mach header, out.\n");
    
    error = uio_addiov(uio_write, CAST_USER_ADDR_T(buf), buf_size);
    if(error) goto __out;
    error = VNOP_WRITE(imgp->ip_vp, uio_write, 0, imgp->ip_vfs_context);
    if(error) goto __out;
    
    
    ret = true;
__out:
    if(uio_read)
        uio_free(uio_read);
    if(uio_write)
        uio_free(uio_write);
    if(buf)
        IOFree(buf, buf_size);
    return ret;
}

#define COPY_BUF_SIZE   (PAGE_SIZE_64 * 32)

static bool
kernel_file_copy(const char *from, const char *to, mode_t mode, vfs_context_t cxt)
{
    kern_return_t error = 0;
    vnode_t src = NULLVP, dst = NULLVP;
    bool ret = false;
    
    error = vnode_lookup(from, 0, &src, cxt);
    if(error) goto __out;
    error = vnode_open(to, O_CREAT | FWRITE, mode, 0, &dst, cxt);
    if(error) goto __out;
    void *buf = IOMalloc(COPY_BUF_SIZE);
    if(NULL == buf) goto __out;
    
    uio_t uio_read = NULL, uio_write = NULL;
    uio_read  = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
    if (uio_read == NULL) goto __out;
    uio_write = uio_create(1, 0, UIO_SYSSPACE, UIO_WRITE);
    if (uio_write == NULL) goto __out;
    
    off_t offset = 0;
    
    while(1) {
        user_size_t write_size;
        // read part
        error = uio_addiov(uio_read, CAST_USER_ADDR_T(buf), COPY_BUF_SIZE);
        if (error) goto __out;

        error = VNOP_READ(src, uio_read, 0, cxt);
        if (error) goto __out;
        
        // check how much bytes we have read. if residual bytes, meaning
        // this is the last loop.
        write_size = COPY_BUF_SIZE - uio_resid(uio_read);
        
        // write part
        error = uio_addiov(uio_write, CAST_USER_ADDR_T(buf), write_size);
        if (error) goto __out;
        
        error = VNOP_WRITE(dst, uio_write, 0, cxt);
        if (error) goto __out;
        
        if(write_size != COPY_BUF_SIZE)
            break;
        
        offset += write_size;
        uio_reset(uio_read,  offset, UIO_SYSSPACE, UIO_READ);
        uio_reset(uio_write, offset, UIO_SYSSPACE, UIO_WRITE);
    }
    
    //DbgPrint("[iemu] remaining... %lld.\n", uio_resid(uio));
    //vnode_getattr
    ret = true;
    
    
__out:
    if(uio_read)
        uio_free(uio_read);
    if(uio_write)
        uio_free(uio_write);
    if(buf)
        IOFree(buf, COPY_BUF_SIZE);
    if(src)
        vnode_put(src);
    if(dst)
        vnode_put(dst);
    
    return ret;
}

#define SHIFTED_BINARY_PATH     "/tmp/"
#define RANDOM_FILE_LEN         12

static bool
get_random_filename(char *filename, size_t size)
{
    size_t l = strlen(SHIFTED_BINARY_PATH);
    int i;
    if(size <= l + RANDOM_FILE_LEN) {
        return false;
    }
    strlcpy(filename, SHIFTED_BINARY_PATH, size);
    for(i = 0; i < RANDOM_FILE_LEN; i ++) {
        filename[i + l] = 'a' + (random() % 26);
    }
    filename[i + l] = '\0';
    return true;
}

#ifdef IOS_SIMULATOR_DEBUG

int
pre_exec_mach_imgact(struct image_params *imgp)
{
    //
    // in ios simulator debug mode, we don't alter the file,
    // cause file is altered in disk. recognize if it is a
    // simulator binary, and insert environment variables.
    
    struct mach_header *mach_header = (struct mach_header *)imgp->ip_vdata;
    bool need_insert = false;
    
    if(mach_header->magic != MH_MAGIC)  // only 32bit is supported for now.
        goto bad_mach;
    
    if(mach_header->flags & MH_EMULATOR)
        need_insert = true;
    //if(!need_insert && strnstr(imgp->ip_strings, "SimpleApp", strlen(imgp->ip_strings)))
    //    need_insert = true;
    
bad_mach:
    
    if(need_insert) {
        vm_address_t addr = 0;
        kern_return_t error = vm_allocate(g_pfncurrent_map(), &addr, page_size, VM_FLAGS_ANYWHERE);
        if(error) goto __out;
        
        if(!reside_environments(imgp, addr, page_size)) {
            error = E2BIG;
            goto __out;
        }

        error = g_pfnexec_mach_imgact(imgp);
__out:
        if(addr)
            vm_deallocate(g_pfncurrent_map(), addr, page_size);
        return error;
    } else {
        return g_pfnexec_mach_imgact(imgp);
    }
}

#else

static
int
pre_exec_mach_imgact_debug_routine(struct image_params *imgp)
{
    vm_address_t addr = 0;
    kern_return_t error = vm_allocate(g_pfncurrent_map(), &addr, page_size, VM_FLAGS_ANYWHERE);
    if(error) goto __out;
    
    if(!reside_environments(imgp, addr, page_size)) {
        error = E2BIG;
        goto __out;
    }
    
    error = g_pfnexec_mach_imgact(imgp);
__out:
    if(addr)
        vm_deallocate(g_pfncurrent_map(), addr, page_size);
    return error;
}

int
pre_exec_mach_imgact(struct image_params *imgp)
{
    struct mach_header *mach_header = (struct mach_header *)imgp->ip_vdata;
    struct fat_header *fat_header = (struct fat_header *)imgp->ip_vdata;
    
    bool need_insert = false;
    
    if((mach_header->magic != MH_MAGIC) &&
       (mach_header->magic != MH_MAGIC_64)) {
        goto bad_mach;
    }
    
    if(mach_header->flags & MH_EMULATOR)
        return pre_exec_mach_imgact_debug_routine(imgp);
    
    //
    // are we looking into an arm file?
    // TODO: we should see subtype if we support that instruction set.
    
    if(mach_header->cputype == CPU_TYPE_ARM) {
        mach_header->cputype    = CPU_TYPE_X86;
        mach_header->cpusubtype = CPU_SUBTYPE_X86_ALL |
            (mach_header->cpusubtype & CPU_SUBTYPE_MASK);
        
        need_insert = true;
        DbgPrint("[iemu] armv7 found.\n");
    } else if(mach_header->cputype == CPU_TYPE_ARM64) {
        mach_header->cputype    = CPU_TYPE_X86_64;
        mach_header->cpusubtype = CPU_SUBTYPE_X86_64_ALL |
            (mach_header->cpusubtype & CPU_SUBTYPE_MASK);
        
        need_insert = true;
        DbgPrint("[iemu] arm64 found.\n");
    }
    
bad_mach:
    //
    // Is it fat?
    
    if((fat_header->magic != FAT_MAGIC) &&
       (fat_header->magic != FAT_CIGAM)) {
        goto bad;
    }
    
    int nfat_arch = 0, f = 0;
    nfat_arch = OSSwapBigToHostInt32(fat_header->nfat_arch);
    for(f = 0; f < nfat_arch; f ++) {
        struct fat_arch *arches = (struct fat_arch *)(fat_header + 1);
        cpu_type_t archtype = OSSwapBigToHostInt32(arches[f].cputype);
        cpu_type_t archsubtype = OSSwapBigToHostInt32(arches[f].cpusubtype) & ~CPU_SUBTYPE_MASK;
        
        if(archtype == CPU_TYPE_ARM) {
            arches[f].cputype       = OSSwapHostToBigInt32(CPU_TYPE_X86);
            arches[f].cpusubtype    = OSSwapHostToBigInt32(CPU_SUBTYPE_X86_ALL |
                                                           (archsubtype & CPU_SUBTYPE_MASK));
            DbgPrint("[iemu] fat armv7 found.\n");
            
        } else if(archtype == CPU_TYPE_ARM64) {
            arches[f].cputype       = OSSwapHostToBigInt32(CPU_TYPE_X86_64);
            arches[f].cpusubtype    = OSSwapHostToBigInt32(CPU_SUBTYPE_X86_64_ALL |
                                                           (archsubtype & CPU_SUBTYPE_MASK));
            DbgPrint("[iemu] fat arm64 found.\n");
        }
    }
    
bad:
    if(need_insert) {
        user_addr_t saved_envv = imgp->ip_user_envv;
        vnode_t saved_ip_vp = imgp->ip_vp;
        
        /* insert environment variables */
        vm_address_t addr = 0;
        kern_return_t error = vm_allocate(g_pfncurrent_map(), &addr, page_size, VM_FLAGS_ANYWHERE);
        if(error) goto __out;
        
        if(!reside_environments(imgp, addr, page_size)) {
            error = E2BIG;
            goto __out;
        }
        
        /* enable execution protection */
        mach_header->flags |= MH_NO_HEAP_EXECUTION;
        /* reset vnode */
        char filename[20];
        get_random_filename(filename, sizeof(filename));
        
        DbgPrint("[iemu] random file name: %s.\n", filename);
        if(!kernel_file_copy(imgp->ip_strings, filename, imgp->ip_vattr->va_mode, imgp->ip_vfs_context)) {
            DbgPrint("[iemu] kernel_file_copy fails.\n");
            error = EACCES;
            goto __out;
        }
        vnode_t repv = NULLVP;
        error = vnode_lookup(filename, 0, &repv, imgp->ip_vfs_context);
        if(error) goto __out;
        
        imgp->ip_vp = repv;
        /* rewrite mach header of the replacement file */
        if(!vfs_manipulate_mach_header(imgp)) {
            DbgPrint("[iemu] vfs_manipulate_mach_header fails.\n");
            error = EINVAL;
            goto __out;
        }
        error = g_pfnexec_mach_imgact(imgp);
        
__out:
        if(repv)
            vnode_put(repv);
        imgp->ip_user_envv = saved_envv;
        imgp->ip_vp = saved_ip_vp;
        if(addr)
            vm_deallocate(g_pfncurrent_map(), addr, page_size);
        return error;

    } else {
        return g_pfnexec_mach_imgact(imgp);
    }
}

#endif


kern_return_t
my_exception_deliver(
    thread_t *thread,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    void *excp,
    lck_mtx_t   *mutex)
{
    
    if(exception == EXC_BAD_ACCESS) {
        /* you may want to pass the exception on */
        return KERN_FAILURE;
    } else {
        return g_pfnexception_deliver(thread, exception, code, codeCnt, excp, mutex);
    }
}






