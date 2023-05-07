#include <assert.h>
#include <string.h> // memcpy
#include <stddef.h> // size_t
#include "include/packet.h"

void packet_write(struct packet *dest, unsigned char *src, int n)
{
    assert(dest);
    assert(sizeof(dest->buf) > (size_t)(dest->size + n));
    if (!src)
        return;
    memcpy(dest->buf + dest->size, src, n);
    dest->size += n;
}

void packet_write_size(struct packet *dest)
{
    assert(dest);
    short size = (short) (dest->size);
    dest->buf[2] = (unsigned char) size;
    dest->buf[3] = (unsigned char) (size >> 8);
}
