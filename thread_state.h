
#ifndef iemukern_thread_state_h
#define iemukern_thread_state_h

#define ARM_THREAD_STATE    1
#define ARM_THREAD_STATE64  6

struct arm_thread_state
{
    __uint32_t  r[13];
    __uint32_t  sp;
    __uint32_t  lr;
    __uint32_t  pc;
    __uint32_t  cpsr;
};

struct arm_thread_state64
{
    __uint64_t  x[29];
    __uint64_t  fp;
    __uint64_t  lr;
    __uint64_t  sp;
    __uint64_t  pc;
    __uint32_t  cpsr;
};


#endif
