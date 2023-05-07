struct packet;

void packet_server_init(struct packet *dest);

void packet_server_account_logon(struct packet *dest);

void packet_server_account_login_proof(struct packet *dest);

void packet_server_net_game_port(struct packet *dest);

void packet_server_enter_chat(struct packet *dest);

void packet_server_friend_list(struct packet *dest);

void packet_server_clan_member_list(struct packet *dest);
