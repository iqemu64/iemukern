
#include "vfs.h"
#include "log.h"
#include <sys/fcntl.h>

kern_return_t
vfs_read_file(void *buffer, vnode_t vnode, off_t offset, size_t size, vfs_context_t cxt)
{
    kern_return_t error = 0;
    
    uio_t uio = NULL;
    uio = uio_create(1, offset, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL) {
        error = KERN_RESOURCE_SHORTAGE;
        goto __out;
    }
    // imitate the kernel and read a single page from the header
    error = uio_addiov(uio, CAST_USER_ADDR_T(buffer), size);
    if (error) goto __out;
    // read kernel vnode into the buffer
    error = VNOP_READ(vnode, uio, 0, cxt);
    
    if (error) goto __out;
    else if (uio_resid(uio)) {
        error = KERN_RESOURCE_SHORTAGE;
        goto __out;
    }
    
    uio_free(uio);
    return error;
__out:
    if(uio)
        uio_free(uio);
    return error;
}

#define COPY_BUF_SIZE   (PAGE_SIZE_64 * 32)

kern_return_t
kernel_file_copy(const char *from, const char *to, mode_t mode, vfs_context_t cxt)
{
    kern_return_t error = 0;
    vnode_t src = NULLVP, dst = NULLVP;
    void *buf = NULL;
    uio_t uio_read = NULL, uio_write = NULL;
    
    while(*from != '=') from ++;
    from ++;
    
    error = vnode_lookup(from, 0, &src, cxt);
    if(error) {
        DbgPrint("[iemu] vnode_lookup in kernel_file_copy fails, from %s, cxt: %p.\n", from, cxt);
        goto __out;
    }
    error = vnode_open(to, O_CREAT | FWRITE, mode, 0, &dst, cxt);
    if(error) {
        DbgPrint("[iemu] vnode_open in kernel_file_copy fails.\n");
        goto __out;
    }
    buf = IOMalloc(COPY_BUF_SIZE);
    if(NULL == buf) {
        DbgPrint("[iemu] IOMalloc in kernel_file_copy fails.\n");
        error = KERN_RESOURCE_SHORTAGE;
        goto __out;
    }
    
    uio_read  = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
    if (uio_read == NULL) {
        DbgPrint("[iemu] uio_create in kernel_file_copy fails.\n");
        error = KERN_RESOURCE_SHORTAGE;
        goto __out;
    }
    uio_write = uio_create(1, 0, UIO_SYSSPACE, UIO_WRITE);
    if (uio_write == NULL) {
        DbgPrint("[iemu] uio_create in kernel_file_copy fails #2.\n");
        error = KERN_RESOURCE_SHORTAGE;
        goto __out;
    }
    
    off_t offset = 0;
    
    while(1) {
        user_size_t write_size;
        // read part
        error = uio_addiov(uio_read, CAST_USER_ADDR_T(buf), COPY_BUF_SIZE);
        if (error) {
            DbgPrint("[iemu] uio_addiov in kernel_file_copy fails.\n");
            goto __out;
        }
        
        error = VNOP_READ(src, uio_read, 0, cxt);
        if (error) {
            DbgPrint("[iemu] VNOP_READ in kernel_file_copy fails.\n");
            goto __out;
        }
        
        // check how much bytes we have read. if residual bytes, meaning
        // this is the last loop.
        write_size = COPY_BUF_SIZE - uio_resid(uio_read);
        
        // write part
        error = uio_addiov(uio_write, CAST_USER_ADDR_T(buf), write_size);
        if (error) {
            DbgPrint("[iemu] uio_addiov in kernel_file_copy fails #2.\n");
            goto __out;
        }
        
        error = VNOP_WRITE(dst, uio_write, 0, cxt);
        if (error) {
            DbgPrint("[iemu] VNOP_WRITE in kernel_file_copy fails.\n");
            goto __out;
        }
        
        if(write_size != COPY_BUF_SIZE)
            break;
        
        offset += write_size;
        uio_reset(uio_read,  offset, UIO_SYSSPACE, UIO_READ);
        uio_reset(uio_write, offset, UIO_SYSSPACE, UIO_WRITE);
    }
    
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
    
    return error;
}

