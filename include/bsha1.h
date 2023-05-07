struct bsha1_password {
    char buf[32]; // max 20.
};

void bsha1_hash_password(struct bsha1_password *dest, struct bsha1_password *src);
