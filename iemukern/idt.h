
#ifndef __iemukern__idt__
#define __iemukern__idt__

#include <stdint.h>
#include <mach/vm_types.h>

//#include "rename_functions.h"

// 16 bytes IDT descriptor, used for 32 and 64 bits kernels (64 bit capable cpus!)
struct descriptor_idt
{
    uint16_t offset_low;
    uint16_t seg_selector;
    uint8_t reserved;
    uint8_t flag;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved2;
};

uint16_t get_size_idt(void);
void get_addr_idt (mach_vm_address_t* idt);


#endif /* defined(__iemukern__idt__) */
