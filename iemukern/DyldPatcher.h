
#ifndef DyldPatcher_h
#define DyldPatcher_h

#ifdef __cplusplus
extern "C" {
#endif

void patchDyld(bool bit64, task_t task);
    
#ifdef __cplusplus
}
#endif

#endif /* DyldPatcher_h */
