struct packet;
struct username;
struct bsha1_password;

// todo: check if this is a good place for this struct.
struct channel_name {
    char buf[32]; // todo: check correct limit.
};

void packet_server_init(struct packet *dest);

void packet_server_account_logon(struct packet *dest, struct username *username);

void packet_server_account_login_proof(struct packet *dest, struct bsha1_password *password);

void packet_server_net_game_port(struct packet *dest);

void packet_server_enter_chat(struct packet *dest);

void packet_server_friend_list(struct packet *dest);

void packet_server_clan_member_list(struct packet *dest);

void packet_server_join_channel(struct packet *dest, struct channel_name *channel);

void packet_server_start_adv_ex3(struct packet *dest);
