#include <assert.h>
#include "include/packet.h"
#include "include/packet_server.h"
#include "include/bsha1.h"

void packet_server_init(struct packet *dest)
{
    assert(dest);
    unsigned char bnet_header = 255;
    packet_write_ex(dest, bnet_header);
    
    unsigned char sid_auth_info = 81;
    packet_write_ex(dest, sid_auth_info);
    
    short packet_size = 0;
    packet_write_ex(dest, packet_size);
    
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
    
    char country[] = "Germany";
    char country_abbr[] = "DEU";
    packet_write_array(dest, country_abbr);
    packet_write_array(dest, country);
    
    packet_write_size(dest);
}

void packet_server_account_logon(struct packet *dest)
{
    assert(dest);
    unsigned char bnet_header = 255;
    unsigned char sid_auth_account_logon = 83;
    short packet_size = 0;
    
    packet_write_ex(dest, bnet_header);
    packet_write_ex(dest, sid_auth_account_logon);
    packet_write_ex(dest, packet_size);
    
    char public_key[32] = {32, 0};
    packet_write_array(dest, public_key);
    
    char username[] = "your-username.";
    packet_write_array(dest, username);
    
    packet_write_size(dest);
}

void packet_server_account_login_proof(struct packet *dest)
{
    assert(dest);
    
    unsigned char bnet_header = 255;
    unsigned char sid_auth_account_login_proof = 84;
    short packet_size = 0;
    
    packet_write_ex(dest, bnet_header);
    packet_write_ex(dest, sid_auth_account_login_proof);
    packet_write_ex(dest, packet_size);
    
    struct bsha1_password password = {"your-password."};
    struct bsha1_password hashed_password = {0};
    bsha1_hash_password(&hashed_password, &password);
    
    assert(sizeof(hashed_password.buf) >= 20);
    packet_write(dest, (unsigned char *) hashed_password.buf, 20);
    
    packet_write_size(dest);
}
