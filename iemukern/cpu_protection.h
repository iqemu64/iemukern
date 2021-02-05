
#ifndef __iemukern__cpu_protection__
#define __iemukern__cpu_protection__

#include <i386/proc_reg.h>

#define enable_interrupts() __asm__ volatile("sti");
#define disable_interrupts() __asm__ volatile("cli");

uint8_t disable_wp(void);
uint8_t enable_wp(void);
uint8_t verify_wp(void);

#endif /* defined(__iemukern__cpu_protection__) */
