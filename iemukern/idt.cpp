
#include "idt.h"

// retrieve the address of the IDT
void
get_addr_idt(mach_vm_address_t *idt)
{
    uint8_t idtr[10];
    __asm__ volatile ("sidt %0": "=m" (idtr));
    *idt = *(mach_vm_address_t *)(idtr+2);
}

// retrieve the size of the IDT
uint16_t
get_size_idt(void)
{
    uint8_t idtr[10];
    uint16_t size = 0;
    __asm__ volatile ("sidt %0": "=m" (idtr));
    size = *((uint16_t *) &idtr[0]);
    return(size);
}
