
#ifndef __iemukern__cpu_protection__
#define __iemukern__cpu_protection__

#include <i386/proc_reg.h>

#define enable_interrupts() __asm__ volatile("sti");
#define disable_interrupts() __asm__ volatile("cli");

#define enable_smap()   do {        \
    if(com_cod_iemukern::smap_supported)    \
        __asm__ volatile("clac");   \
} while(0);

#define disable_smap()  do {        \
    if(com_cod_iemukern::smap_supported)    \
        __asm__ volatile("stac");   \
} while(0);

#ifdef __cplusplus
extern "C" {
#endif

uint8_t disable_wp(void);
uint8_t enable_wp(void);
uint8_t verify_wp(void);
    
#ifdef __cplusplus
}
#endif

#endif /* defined(__iemukern__cpu_protection__) */
