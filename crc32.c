#include <assert.h>
#include "include/crc32.h"

#define CRC32_POLYNOMIAL (0x04c11db7)
static unsigned int table[256] = {0};

static unsigned int reflect(unsigned int reflect, char c)
{
    unsigned int value = 0;

    for (int pos = 1; pos < (int) (c + 1); pos++) {
        if (reflect & 1)
            value |= 1 << (c - pos);
        reflect >>= 1;
    }

    return value;
}

static void partial(unsigned int *crc, unsigned char *src, unsigned int size)
{
    assert(crc);
    assert(src);
    while (size--)
        *crc = (*crc >> 8) ^ table[(*crc & 0xFF) ^ *src++];
}

unsigned int crc_full(unsigned char *src, unsigned int size)
{
    static int table_initialized = 0;

    assert(src);

    if (!table_initialized) {
        table_initialized = 1;
        for (unsigned int codes = 0; codes <= 0xFF; codes++) {
            table[codes] = reflect(codes, 8) << 24;
            for (unsigned int pos = 0; pos < 8; pos++)
                table[codes] = (table[codes] << 1) ^ (table[codes] & (1 << 31) ? CRC32_POLYNOMIAL : 0);
            table[codes] = reflect(table[codes], 32);
        }
    }

    unsigned int crc = 0xFFFFFFFF;
    partial(&crc, src, size);
    return crc ^ 0xFFFFFFFF;
}
