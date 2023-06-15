struct sha1;
struct sha1_hash;

void sha1_update(struct sha1 *sha1, unsigned char *data,  unsigned int len);
void sha1_final(struct sha1 *sha1);
void sha1_get_hash(struct sha1_hash *dest, struct sha1 *src);
