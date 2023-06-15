struct packet;
struct username;
struct key_info_roc;
struct key_info_tft;
struct exe_info;
struct public_key;
struct map;

void packet_server_init(struct packet *dest);

void packet_server_ping(struct packet *dest, int ping);

void packet_server_account_logon(struct packet *dest, struct username *username);

void packet_server_net_game_port(struct packet *dest);

void packet_server_enter_chat(struct packet *dest);

void packet_server_friend_list(struct packet *dest);

void packet_server_clan_member_list(struct packet *dest);

void packet_server_start_adv_ex3(struct packet *dest, struct map *map);

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

void packet_server_sid_net_game_port(struct packet *dest, unsigned short port);

void packet_server_sid_enter_chat(struct packet *dest);

void packet_server_sid_join_channel(struct packet *dest, struct channel *channel);
