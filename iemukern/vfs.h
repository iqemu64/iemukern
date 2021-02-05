
#ifndef vfs_h
#define vfs_h

#include <sys/vnode.h>

#ifdef __cplusplus
extern "C" {
#endif

kern_return_t vfs_read_file(void *buffer, vnode_t vnode, off_t offset, size_t size, vfs_context_t cxt);
kern_return_t kernel_file_copy(const char *from, const char *to, mode_t mode, vfs_context_t cxt);
    
#ifdef __cplusplus
}
#endif

#endif /* vfs_h */
