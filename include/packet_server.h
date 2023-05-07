struct packet;

void packet_server_init(struct packet *dest);

void packet_server_account_logon(struct packet *dest);

void packet_server_account_login_proof(struct packet *dest);
