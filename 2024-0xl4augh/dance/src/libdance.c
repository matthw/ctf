#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include "chacha20.h"


#define BUFF_SIZE 256
#define PATH_MAX 4096

//#define DEBUG

uint32_t crc32(char *buf, size_t len);
uint8_t crc_check();

__attribute__((constructor)) static void init() {
    uint8_t zob = crc_check();
}


/*
 * exit() syscall
 */
__attribute__((__visibility__("hidden"))) void sys_exit(int status)
{
    __asm__ volatile(
                        "mov $58, %%rax\n"
                        "mov %0, %%rdi\n"
                        "add $2, %%rax\n"
                        "syscall" : : "g"(status));
}

/*
 * find nop marker between start and end addresses
 */
__attribute__((__visibility__("hidden"))) uint64_t find_marker(uint8_t *start, uint64_t end)
{
    while ((uint64_t)start < (uint64_t)(end - 8))
    {
        if ( ((*(start + 0)) == 0x66) && ((*(start + 1)) == 0x0f) && ((*(start + 2)) == 0x1f) && ((*(start + 3)) == 0x84) && \
             ((*(start + 4)) == 0x00) && ((*(start + 5)) == 0x00) && ((*(start + 6)) == 0x00) && \
             ((*(start + 7)) == 0x00) && ((*(start + 8)) == 0x00))
              break;
        start++;
    }

    if ((uint64_t)start == end - 8)
          return 0;
    return (uint64_t)start;
}


/*
 * find 2 markers in .text and do crc check
 */
__attribute__((__visibility__("hidden"))) uint8_t crc_check()
{
    FILE *fp;
    ssize_t n;

    char bf[PATH_MAX+1024];
    uint64_t start;
    uint64_t end;
    char prot[5];
    uint64_t pgoff;
    uint16_t min, maj;
    char execname[PATH_MAX];
    unsigned int ino;

    if ((fp = fopen("/proc/self/maps", "r")) == NULL) {
        #ifdef DEBUG
        puts("bail at fopen");
        #endif
        puts("i'm dead");
        sys_exit(1);
        return 1;
    }

    while (1)
    {

        if (fgets(bf, sizeof(bf), fp) == NULL)
            break;

        strcpy(execname, "");
        /* 00400000-0040c000 r-xp 00000000 fd:01 41038  /bin/cat */
        n = sscanf(bf, "%"PRIx64"-%"PRIx64" %s %"PRIx64" %x:%x %u %s\n",
                &start, &end, prot, &pgoff, &maj, &min, &ino, execname);

        /* found first r-x */
        if (prot[0] == 'r' && prot[2] == 'x')
              break;
    }
    fclose(fp);

    #ifdef DEBUG
    printf("%p %p %s %s\n", start, end, prot, execname);
    #endif

    /* find markers */
    uint64_t m_start = find_marker((uint8_t *)(start + 0x100), end);
    #ifdef DEBUG
    printf("%p\n", m_start);
    #endif
    if (m_start == 0)
          sys_exit(42);

    uint64_t m_end   = find_marker((uint8_t *)(m_start + 16), end);
    #ifdef DEBUG
    printf("%p\n", m_end);
    #endif
    if (m_end == 0)
          sys_exit(42);


    uint32_t crc = crc32((void *)m_start, m_end-m_start);

    //uncomment to dump crc and fix the value below
    //printf("text_crc: %p\n", crc);

    if (crc != 0x5285f228) {
        #ifdef DEBUG
        puts("wrong crc");
        #endif
        puts("i'm dead");
        sys_exit(42);
        return 1;
    }

    return 0;
}

/*
 * skip lib function
 */
__attribute__((__visibility__("hidden"))) int my_memcmp(void *b, void *c, int len)
{
    unsigned char *p = b;
    unsigned char *q = c;

    while (len > 0)
    {
        if (*p != *q)
            return (*p - *q);
        len--;
        p++;
        q++;
    }
    return 0;
}


uint8_t dance_with_me(char *flag)
{
    uint8_t chk;

    uint8_t enc[] = {
        183, 224, 93, 232, 102, 174, 174, 106, 217, 15, 58, 87, 87, 203, 183, 123, 254, 70, 154, 10, 248, 47, 248, 99, 92, 94, 188, 139, 246, 116, 245, 102, 97, 151, 241, 17, 197, 105, 108, 213, 219, 221, 32, 36, 54, 138, 108, 47, 254
    };

    uint8_t key[] = {
        108, 123, 177, 238, 10, 76, 71, 157, 237, 215, 91, 188, 210, 67, 221,
        64, 29, 178, 119, 184, 53, 110, 89, 75, 248, 99, 38, 215, 226, 80, 237, 219
    };

    uint8_t nonce[] = {
        150, 191, 235, 202, 142, 124, 251, 188, 217, 114, 168, 83
    };

    struct chacha20_context ctx;
    size_t input_len = strlen(flag);


    chacha20_init_context(&ctx, key, nonce, 0);
    if ((chk = crc_check()) == 1) {
        puts("i'm dead");
        return 1;
    }
    chacha20_xor(&ctx, flag, input_len);

    if (input_len < sizeof(enc))
          return 1;
    if (!my_memcmp(flag, enc, sizeof(enc)))
          return 0;
    return 1;
}
