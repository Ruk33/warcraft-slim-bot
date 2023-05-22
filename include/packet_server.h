struct packet;
struct username;
struct bsha1_password;

// todo: check if this is a good place for this struct.
struct channel_name {
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

struct hashed_password {
    char buf[20];
};

void packet_server_init(struct packet *dest);

void packet_server_ping(struct packet *dest, int ping);

void packet_server_account_logon(struct packet *dest, struct username *username);

void packet_server_account_login_proof(struct packet *dest, struct bsha1_password *password);

void packet_server_net_game_port(struct packet *dest);

void packet_server_enter_chat(struct packet *dest);

void packet_server_friend_list(struct packet *dest);

void packet_server_clan_member_list(struct packet *dest);

void packet_server_join_channel(struct packet *dest, struct channel_name *channel);

void packet_server_start_adv_ex3(struct packet *dest);

void packet_server_sid_auth_check(struct packet *dest,
                                  unsigned int client_token,
                                  unsigned int exe_version,
                                  unsigned long exe_version_hash,
                                  struct key_info_roc *key_info_roc,
                                  struct key_info_tft *key_info_tft,
                                  struct exe_info *exe_info);

void packet_server_sid_auth_account_logon(struct packet *dest,
                                          struct username *username,
                                          struct public_key *public_key);

void packet_server_sid_auth_account_logon_proof(struct packet *dest,
                                                struct hashed_password *hp);
