#include <assert.h>
#include <string.h> // memcpy, strlen
#include "include/bsha1.h"

// all credits to Josko/aura-bot/blob/master/bncsutil/src/bncsutil/bsha1.cpp

#define BSHA_IC1 0x67452301lu
#define BSHA_IC2 0xEFCDAB89lu
#define BSHA_IC3 0x98BADCFElu
#define BSHA_IC4 0x10325476lu
#define BSHA_IC5 0xC3D2E1F0lu

#define BSHA_OC1 0x5A827999lu
#define BSHA_OC2 0x6ED9EBA1lu
#define BSHA_OC3 0x70E44324lu
#define BSHA_OC4 0x359D3E2Alu

#define LSB2(num) (num)
#define LSB4(num) (num)
#define ROL(a,b) (((a) << (b)) | ((a) >> 32 - (b)))

#define BSHA_COP e = d; d = c; c = ROL(b, 30); b = a; a = g;

#define BSHA_OP1(a, b, c, d, e, f, g) g = LSB4(f) + ROL(a, 5) + e + \
((b & c) | (~b & d)) + BSHA_OC1; BSHA_COP

#define BSHA_OP2(a, b, c, d, e, f, g) g = (d ^ c ^ b) + e + ROL(g, 5) + \
LSB4(f) + BSHA_OC2; BSHA_COP

#define BSHA_OP3(a, b, c, d, e, f, g) g = LSB4(f) + ROL(g, 5) + e + \
((c & b) | (d & c) | (d & b)) - BSHA_OC3; BSHA_COP

#define BSHA_OP4(a, b, c, d, e, f, g) g = (d ^ c ^ b) + e + ROL(g, 5) + \
LSB4(f) - BSHA_OC4; BSHA_COP

void bsha1_hash_password(struct bsha1_password *dest, struct bsha1_password *src)
{
    assert(dest);
    assert(src);
    
    // make sure the last character is the null terminator.
    // preventing overflows is always good :)
    src->buf[sizeof(src->buf) - 1] = 0;
    
    char *input = src->buf;
    int length = (int) strlen(src->buf);
    char *result = dest->buf;
    
    int i = 0;
    unsigned int a, b, c, d, e, g = 0;
    unsigned int* ldata = 0;
    char data[1024] = {0};
    memcpy(data, input, length);
    ldata = (unsigned int *) data;
    
    for (i = 0; i < 64; i++) {
        ldata[i + 16] =
            LSB4(ROL(1, LSB4(ldata[i] ^ ldata[i+8] ^ ldata[i+2] ^ ldata[i+13]) % 32));
    }
    
    a = BSHA_IC1;
    b = BSHA_IC2;
    c = BSHA_IC3;
    d = BSHA_IC4;
    e = BSHA_IC5;
    g = 0;
    
    // Loops unrolled.
    BSHA_OP1(a, b, c, d, e, *ldata++, g); 
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    BSHA_OP1(a, b, c, d, e, *ldata++, g);
    
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    BSHA_OP2(a, b, c, d, e, *ldata++, g);
    
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    BSHA_OP3(a, b, c, d, e, *ldata++, g);
    
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    BSHA_OP4(a, b, c, d, e, *ldata++, g);
    
    ldata = (unsigned int *) result;
    ldata[0] = LSB4(BSHA_IC1 + a);
    ldata[1] = LSB4(BSHA_IC2 + b);
    ldata[2] = LSB4(BSHA_IC3 + c);
    ldata[3] = LSB4(BSHA_IC4 + d);
    ldata[4] = LSB4(BSHA_IC5 + e);
    ldata = 0;
}