#include <assert.h>
#include "include/packet.h"
#include "include/packet_server.h"
#include "include/bsha1.h"

static void packet_write_header(struct packet *dest, unsigned char packet_type)
{
    assert(dest);
    
    unsigned char bnet_header = 255;
    packet_write_ex(dest, bnet_header);
    
    packet_write_ex(dest, packet_type);
    
    short packet_size = 0;
    packet_write_ex(dest, packet_size);
}

void packet_server_init(struct packet *dest)
{
    assert(dest);
    unsigned char sid_auth_info = 81;
    packet_write_header(dest, sid_auth_info);
    
    unsigned char protocol_id[] = {0, 0, 0, 0};
    unsigned char platform_id[] = {54, 56, 88, 73}; // "IX86"
    unsigned char product_id[] = {80, 88, 51, 87}; // "W3XP"
    unsigned char version_id[] = {0, 0, 0, 0};
    unsigned char language[] = {83, 85, 110, 101}; // "enUS"
    unsigned char local_ip[] = {127, 0, 0, 1};
    unsigned char time_zone_bias[] = {60, 0, 0, 0}; // 60 minutes (GMT +0100) but this is probably -0100
    
    packet_write_array(dest, protocol_id);
    packet_write_array(dest, platform_id);
    packet_write_array(dest, product_id);
    packet_write_array(dest, version_id);
    packet_write_array(dest, language);
    packet_write_array(dest, local_ip);
    packet_write_array(dest, time_zone_bias);
    
    int locale_id = 1031; // not sure, but let's see if it works with it.
    packet_write_ex(dest, locale_id);
    packet_write_ex(dest, locale_id);
    
    char country_abbr[] = "DEU";
    packet_write_array(dest, country_abbr);
    
    char country[] = "Germany";
    packet_write_array(dest, country);
    
    packet_write_size(dest);
}

void packet_server_account_logon(struct packet *dest)
{
    assert(dest);
    
    unsigned char sid_auth_account_logon = 83;
    packet_write_header(dest, sid_auth_account_logon);
    
    char public_key[32] = {32, 0};
    packet_write_array(dest, public_key);
    
    char username[] = "your-username.";
    packet_write_array(dest, username);
    
    packet_write_size(dest);
}

void packet_server_account_login_proof(struct packet *dest)
{
    assert(dest);
    
    unsigned char sid_auth_account_login_proof = 84;
    packet_write_header(dest, sid_auth_account_login_proof);
    
    struct bsha1_password password = {"your-password."};
    struct bsha1_password hashed_password = {0};
    bsha1_hash_password(&hashed_password, &password);
    
    assert(sizeof(hashed_password.buf) >= 20);
    packet_write(dest, (unsigned char *) hashed_password.buf, 20);
    
    packet_write_size(dest);
}

void packet_server_net_game_port(struct packet *dest)
{
    assert(dest);
    unsigned char net_game_port = 69;
    packet_write_header(dest, net_game_port);
    
    unsigned short port = 6112;
    packet_write_ex(dest, port);
    
    packet_write_size(dest);
}

void packet_server_enter_chat(struct packet *dest)
{
    assert(dest);
    unsigned char enter_chat = 10;
    packet_write_header(dest, enter_chat);
    short empty = 0;
    packet_write_ex(dest, empty);
    packet_write_size(dest);
}

void packet_server_friend_list(struct packet *dest)
{
    assert(dest);
    unsigned char friend_list = 101;
    packet_write_header(dest, friend_list);
    packet_write_size(dest);
}

void packet_server_clan_member_list(struct packet *dest)
{
    assert(dest);
    unsigned char clan_member_list = 125;
    packet_write_header(dest, clan_member_list);
    int empty = 0;
    packet_write_ex(dest, empty);
    packet_write_size(dest);
}
