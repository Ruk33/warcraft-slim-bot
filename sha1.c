#include <assert.h>
#include <string.h> // memcpy, memset
#include "include/types.h"
#include "include/sha1.h"

typedef union {
    unsigned char c[64];
    unsigned int l[16];
} SHA1_WORKSPACE_BLOCK;

// rotate x bits to the left
#define ROL32(value, bits) (((value)<<(bits))|((value)>>(32-(bits))))

// little endian
#define SHABLK0(i) (block->l[i] = (ROL32(block->l[i],24) & 0xFF00FF00) \
| (ROL32(block->l[i],8) & 0x00FF00FF))

#define SHABLK(i) (block->l[i&15] = ROL32(block->l[(i+13)&15] ^ block->l[(i+8)&15] \
^ block->l[(i+2)&15] ^ block->l[i&15],1))

// SHA-1 rounds
#define R0(v,w,x,y,z,i) { z+=((w&(x^y))^y)+SHABLK0(i)+0x5A827999+ROL32(v,5); w=ROL32(w,30); }
#define R1(v,w,x,y,z,i) { z+=((w&(x^y))^y)+SHABLK(i)+0x5A827999+ROL32(v,5); w=ROL32(w,30); }
#define R2(v,w,x,y,z,i) { z+=(w^x^y)+SHABLK(i)+0x6ED9EBA1+ROL32(v,5); w=ROL32(w,30); }
#define R3(v,w,x,y,z,i) { z+=(((w|x)&y)|(w&x))+SHABLK(i)+0x8F1BBCDC+ROL32(v,5); w=ROL32(w,30); }
#define R4(v,w,x,y,z,i) { z+=(w^x^y)+SHABLK(i)+0xCA62C1D6+ROL32(v,5); w=ROL32(w,30); }

static void transform(unsigned int *state, unsigned char *buffer)
{
	unsigned int a = 0, b = 0, c = 0, d = 0, e = 0;
    
	SHA1_WORKSPACE_BLOCK* block = 0;
	static unsigned char workspace[64] = {0};
	block = (SHA1_WORKSPACE_BLOCK *)workspace;
    
    // dont like this.
	memcpy(block, buffer, 64);
    
	// Copy state[] to working vars
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
    
	// 4 rounds of 20 operations each. Loop unrolled.
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    
	// Add the working vars back into state[]
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
    
	// Wipe variables
	a = 0; b = 0; c = 0; d = 0; e = 0;
}

void sha1_update(struct sha1 *sha1, unsigned char *data, unsigned int len)
{
    assert(sha1);
    assert(data);
    
    if (!sha1->initialized) {
        sha1->initialized = 1;
        sha1->state[0] = 0x67452301;
        sha1->state[1] = 0xEFCDAB89;
        sha1->state[2] = 0x98BADCFE;
        sha1->state[3] = 0x10325476;
        sha1->state[4] = 0xC3D2E1F0;
    }
    
    unsigned int i = 0, j = 0;
    
	j = (sha1->count[0] >> 3) & 63;
    
	if ((sha1->count[0] += len << 3) < (len << 3))
        sha1->count[1]++;
    
	sha1->count[1] += (len >> 29);
    
	if ((j + len) > 63) {
		memcpy(sha1->buffer + j, data, (i = 64 - j));
		transform(sha1->state, sha1->buffer);
        
		for (; i+63 < len; i += 64)
			transform(sha1->state, data + i);
        
		j = 0;
	} else {
        i = 0;
    }
    
	memcpy(sha1->buffer + j, data + i, len - i);
}

void sha1_final(struct sha1 *sha1)
{
    assert(sha1);
    
    unsigned int i = 0;
	unsigned char finalcount[8] = {0};
    
	for (i = 0; i < 8; i++)
		finalcount[i] = (unsigned char)((sha1->count[(i >= 4 ? 0 : 1)]
                                         >> ((3 - (i & 3)) * 8) ) & 255); // Endian independent
    
	sha1_update(sha1, (unsigned char *)"\200", 1);
    
	while ((sha1->count[0] & 504) != 448)
		sha1_update(sha1, (unsigned char *)"\0", 1);
    
	sha1_update(sha1, finalcount, 8); // Cause a SHA1Transform()
    
	for (i = 0; i < 20; i++)
		sha1->digest.buf[i] = (unsigned char)((sha1->state[i >> 2] >> ((3 - (i & 3)) * 8) ) & 255);
    
	// Wipe variables for security reasons
	i = 0;
    *sha1 = (struct sha1) {0};
	memset(finalcount, 0, 8);
    
	transform(sha1->state, sha1->buffer);
}

void sha1_get_hash(struct sha1_hash *dest, struct sha1 *src)
{
    assert(dest);
    assert(src);
    *dest = src->digest;
}
