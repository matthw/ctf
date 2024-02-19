// compile with gcc nano.c -no-pie -o nano
// adding optimization will screw it up
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#define PTRACE_SYSCALL func_00101189
#define JZJNZ __asm__ volatile(".byte 0x74,0x03,0x75,0x01,0xe8\n");

// encrypted flag
uint8_t flag[] = {12, 92, 96, 32, 105, 99, 100, 15, 79, 30, 51, 58, 104, 42, 124, 217, 213, 208, 201, 231, 195, 240, 188, 171, 155, 215, 152, 139, 175, 176, 248, 71, 73, 22, 73, 104};

// fake troll key
uint8_t KEY[] =  {123, 61, 20, 67, 1, 67, 94, 47, 39, 106, 71, 74, 27, 16, 83, 246, 172, 191, 188, 147, 182, 222, 222, 206, 180, 179, 201, 252, 155, 199, 193, 16, 46, 78, 42, 57};


/* just ptrace() but without libc just to fuck around
 */
long func_00101189(long request, long pid, void *addr, void *data)
{
    long ret; 

    __asm__ volatile(
                        "mov $79, %%rax\n"
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        ".byte 0x74,0x03,0x75,0x01,0xe8\n"
                        "xor $42, %%rax\n"
                        "mov %3, %%r10\n"
                        "syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data));
    asm("mov %%rax, %0" : "=r"(ret));
    return ret; 
}

int check(uint8_t *f)
{
    int max = strlen(f);
    int meh = 0;
    register int k asm ("r12"); /* r12 holds the xorkey */

    for (uint8_t i = 0; i < 36; i++)
    {
        if (i > max)
              return 1;

        /* load fake key please decompilers :p */
        k = KEY[i];

        /* trigger sigsegv and crash */
        asm("mov (0), %r11\n");

        /* here the father catched the sigsegv and set the correct key in r12 */
        uint8_t c = flag[i];
        uint8_t e = f[i]^(k&0xff);

        if (e != c)
              meh = 1;
    }
    return meh;
}


int main(int argc, char **argv)
{

    pid_t pid;
    int status;
    struct user_regs_struct regs;
    int lol = 0;
    uint8_t k;
    struct user_regs_struct *tmp;
    

    if (argc != 2) {
        printf("usage: %s <flag>\n", argv[0]);
        exit(1);
    }



    /* child */
    if ((pid = fork()) == 0)
    {
        JZJNZ;
        PTRACE_SYSCALL(PTRACE_TRACEME, pid, NULL, NULL);
        if (check(argv[1]) == 0)
              puts("yes");
        else
              puts("no");
        exit(0);
    }

    /* parent */
    PTRACE_SYSCALL(PTRACE_ATTACH, pid, NULL, NULL);
    while (1)
    {
        waitpid(pid, &status, 0);

        if (WIFEXITED(status))
            break;

        if (WIFCONTINUED(status))
              continue;

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
        {
            // compute real key
            lol += 1;
            k = ((lol << 3) & 0xff);
            JZJNZ;
            k ^= 0xca;
            JZJNZ;
            k |= (lol >> 5);
            JZJNZ;
            k ^= 0xfe;

            /* fix dead child and revive it, stronger than jesus */
            JZJNZ;
            PTRACE_SYSCALL(PTRACE_GETREGS, pid, NULL, &regs);
            tmp = &regs;

            regs.r12 = 0x7ffc9286a800 | k;       // set real key to r12 reg of the child
            regs.rip += 8;      // skip the 8 bytes of the mov r12, [0]
                                
            PTRACE_SYSCALL(PTRACE_SETREGS, pid, NULL, &regs);
            tmp = &regs;
            JZJNZ;
        }
        JZJNZ;
        PTRACE_SYSCALL(PTRACE_CONT, pid, NULL, NULL);
    }



    return 0;
}


