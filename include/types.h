struct server_name {
    char buf[256];
};

struct server_salt {
    unsigned char buf[32];
};

struct ver_file_name {
    char buf[15];
};

struct value_string_formula {
    char buf[63];
};

struct commonj {
    unsigned char buf[512000]; // seems like the original size is 347kb
    long size;
};

struct blizzardj {
    unsigned char buf[512000]; // seems like the original size is 460kb
    long size;
};

// todo: check if this is a good place for this struct.
struct channel {
    char buf[32]; // todo: check correct limit.
};

struct cd_key_roc {
    char buf[27]; // seems like the size is 26, plus null terminator.
};

struct cd_key_tft {
    char buf[27]; // seems like the size is 26, plus null terminator.
};

struct key_info_roc {
    char buf[20];
};

struct key_info_tft {
    char buf[20];
};

struct exe_info {
    // including null terminator.
    char buf[34];
};

struct public_key {
    char buf[32];
};

struct salt {
    unsigned char buf[32];
};

struct server_key {
    unsigned char buf[32];
};

struct username {
    char buf[32]; // todo > check if this is the correct limit.
};

struct password {
    char buf[20];
};

struct hashed_password {
    char buf[20];
};

struct sha1_hash {
    unsigned char buf[20];
};

struct sha1 {
    int initialized;
    unsigned int state[5];
	unsigned int count[2];
	unsigned char buffer[64];
    struct sha1_hash digest;
};

struct map {
    unsigned char buf[1024 * 1024 * 128];
    char path[256];
    long size;
    unsigned int crc;
    struct commonj commonj;
    struct blizzardj blizzardj;
    unsigned int width; // todo: check for proper type.
    unsigned int height; // todo: check for proper type.
    unsigned int options;
    unsigned int number_players;
    unsigned int filter_type;
    unsigned int number_teams;
    struct sha1 sha1;
    // unsigned int crc;
};
