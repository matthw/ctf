#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <errno.h>

#include "chacha20.h"
#include "dance.h"
#include "dance_ops.h"

//#define DEBUG

/*
 * TODO:
 *  suffer
 */

uint8_t dance_with_me(char *flag);
uint32_t crc32(char *buf, size_t len);


/* just ptrace() but without libc just to fuck around
 */
long _ptrace(long request, long pid, void *addr, void *data)
{
    long ret;

    __asm__ volatile(
                        "mov $79, %%rax\n"
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        ".byte 0x74,0x03,0x75,0x01,0xe8\n"
                        ".byte 0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00\n"
                        "xor $42, %%rax\n"
                        "mov %3, %%r10\n"
                        //"mov $101, %%rax\n"
                        "syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data));
    asm("mov %%rax, %0" : "=r"(ret));
    return ret;
}



/*
 * stolen with love from 
 * https://github.com/elfmaster/saruman/blob/master/launcher.c
 */
int pid_write(int pid, void *dest, const void *src, size_t len)
{
    size_t rem = len % sizeof(void *);
    size_t quot = len / sizeof(void *);
    unsigned char *s = (unsigned char *) src;
    unsigned char *d = (unsigned char *) dest;

    while (quot-- != 0) {
        #ifdef DEBUG
        printf("pid_write(addr = 0x%llx)\n", d);
        #endif


        if (_ptrace(PTRACE_POKEDATA, pid, d, *(void **)s) == -1 )
            goto out_error;
            s += sizeof(void *);
            d += sizeof(void *);
    }

    if (rem != 0) {
        long w;
        unsigned char *wp = (unsigned char *)&w;

        /* 
        PTRACE_PEEK* kernel and libc exposed API are not the same
        libc returns peeked data in eax, kernel does in *addr
        */
        //w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
        _ptrace(PTRACE_PEEKDATA, pid, d, &w);
        if (w == -1 && errno != 0) {
            d -= sizeof(void *) - rem;

            //w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
            _ptrace(PTRACE_PEEKDATA, pid, d, &w);
            if (w == -1 && errno != 0)
                  goto out_error;

            wp += sizeof(void *) - rem;
        }

        while (rem-- != 0)
              wp[rem] = s[rem];

        if (_ptrace(PTRACE_POKEDATA, pid, (void *)d, (void *)w) == -1)
              goto out_error;
    }

    return 0;

out_error:
    //fprintf(stderr, "pid_write() failed, pid: %d: %s\n", pid, strerror(errno));
    return -1;
}

/* main nanomite stuff */
void lets_go(char *flag)
{
    int fd;
    char libpath[256];
    pid_t pid;
    uint8_t (*dance_with_me)(uint8_t *);
    int status;
    struct user_regs_struct regs;
    uint32_t base_addr, crc;
    uint64_t prev_size, prev_addr = 0;

    /* child */
    if ((pid = fork()) == 0)
    {
        _ptrace(PTRACE_TRACEME, pid, NULL, NULL);

        /* open memfd */
        fd = memfd_create("", 0);
        sprintf(libpath, "/proc/self/fd/%d", fd);

        /* decrypt */
        struct chacha20_context ctx;
        uint8_t key[] = {72, 101, 108, 108, 111, 44, 32, 116, 104, 97, 116, 32, 105, 115, 32, 111, 110, 101, 32, 107, 101, 121, 32, 102, 111, 114, 32, 121, 111, 117, 46, 46};
        uint8_t nonce[] = {110, 105, 99, 101, 95, 109, 111, 118, 101, 95, 58, 41};
        chacha20_init_context(&ctx, key, nonce, 0);
        chacha20_xor(&ctx, (uint8_t *)&libdata, libsize);

        /* copy data */
        ssize_t sz = libsize;
        ssize_t written;

        while (sz > 0) {
            written = write(fd, libdata + (libsize - sz), sz);
            sz -= written;
        }


        //void *libdance = dlopen("./libdance.so", RTLD_NOW);
        void *libdance = dlopen(libpath, RTLD_NOW);
        dance_with_me = dlsym(libdance, "dance_with_me");
        #ifdef DEBUG
        printf("dance_with_me: %p\n", dance_with_me);
        #endif

        if (!dance_with_me(flag))
            puts("ok");
        else
            puts("nop");

        dlclose(libdance);
        exit(0);
    }

    /* parent */
    _ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    while (1)
    {
        waitpid(pid, &status, 0);

        if (WIFEXITED(status))
              break;

        if (WIFCONTINUED(status))
              continue;

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        //if ((WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) || (WIFSTOPPED(status) && WSTOPSIG(status) == SIGILL))
        {

            if (prev_size != 0 && prev_addr != 0) {
                #ifdef DEBUG
                printf("patchback @ 0x%x : %d\n", prev_addr, prev_size);
                #endif
                pid_write(pid, (void *)prev_addr, "\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc", prev_size);
            }


            _ptrace(PTRACE_GETREGS, pid, NULL, &regs);


            base_addr = (regs.rip - 1) & 0xfff;
            crc = ~crc32((uint8_t *)&base_addr, 4);

            #ifdef DEBUG
            printf("crashed @ %p\n", regs.rip);
            printf("crc32:    0x%x\n", crc);
            #endif

            /* look for instruction and patch it */
            uint32_t i = -1;
            do {
                i++;
                if (insns[i].crc32 == crc) {
                    break;
                }
            } while (insns[i].crc32 != 0);

            #ifdef DEBUG
            for (int v = 0; v < insns[i].num_ins; v++)
                  printf("0x%02x ", insns[i].code[v]);
            puts("");
            #endif

            pid_write(pid, (void *)(regs.rip - 1), insns[i].code, insns[i].num_ins);

            // backup for patchback
            prev_size = insns[i].num_ins;
            prev_addr = regs.rip -1;


            regs.rip -= 1;
            _ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        }

        _ptrace(PTRACE_CONT, pid, NULL, NULL);
    }
}


/* entry */
int main(int argc, char **argv)
{
    pid_t pid;
    int status;

    if (argc != 2) {
        printf("usage: %s <flag>\n", argv[0]);
        exit(1);
    }

    //lets_go(argv[1]);
    //exit(0);

    /* fork and attach */
    if ((pid = fork()) == 0) {
        lets_go(argv[1]);
    }

    /* trace child */
    _ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    while (1) {
        waitpid(pid, &status, 0); 

        if (WIFEXITED(status))
              break;
        if (WIFCONTINUED(status))
              continue;
        _ptrace(PTRACE_CONT, pid, NULL, NULL);
    }   
}
