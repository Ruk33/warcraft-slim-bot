struct sha1_hash {
    unsigned char buf[20];
};

struct sha1 {
    int initialized;
    unsigned int state[5];
	unsigned int count[2];
	unsigned char buffer[64];
	unsigned char digest[20];
    // struct sha1_hash digest;
};

void sha1_update(struct sha1 *sha1,
                 unsigned char *data, 
                 unsigned int len);
void sha1_final(struct sha1 *sha1);
void sha1_get_hash(struct sha1_hash *dest, struct sha1 *src);
