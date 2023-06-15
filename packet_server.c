#include <assert.h>
#include <string.h> // strnlen
#include "include/types.h"
#include "include/packet.h"
#include "include/packet_server.h"
#include "include/game.h"

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
    unsigned char sid_auth_info = 80; // was 81.
    packet_write_header(dest, sid_auth_info);
    
    unsigned char protocol_id[] = {0, 0, 0, 0};
    unsigned char platform_id[] = {54, 56, 88, 73}; // "IX86"
    // unsigned char product_id[] = {80, 88, 51, 87}; // "W3XP"
    unsigned int product_id = 0x1E;
    unsigned char version_id[] = {27, 0, 0, 0};
    unsigned char language[] = {83, 85, 110, 101}; // "enUS"
    unsigned char local_ip[] = {127, 0, 0, 1};
    unsigned char time_zone_bias[] = {60, 0, 0, 0}; // 60 minutes (GMT +0100) but this is probably -0100
    
    packet_write_array(dest, protocol_id);
    packet_write_array(dest, platform_id);
    packet_write_ex(dest, product_id);
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

void packet_server_ping(struct packet *dest, int ping)
{
    assert(dest);
    unsigned char packet_type = 37;
    packet_write_header(dest, packet_type);
    packet_write_ex(dest, ping);
    packet_write_size(dest);
}

void packet_server_account_logon(struct packet *dest, struct username *username)
{
    assert(dest);
    
    unsigned char sid_auth_account_logon = 83;
    packet_write_header(dest, sid_auth_account_logon);
    
    char public_key[32] = {32, 0}; // todo: complete!
    packet_write_array(dest, public_key);
    
    packet_write_array(dest, username->buf);
    
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

// note: should we change the weird name to something like
// start game, create game, or...?
void packet_server_start_adv_ex3(struct packet *dest,
                                 struct map *map)
{
    assert(dest);
    assert(map);
    
    unsigned char packet_type = 0x1C;
    packet_write_header(dest, packet_type);
    
    /* unsigned */ char stat_string[512] = {0};
    
    unsigned int map_flags = 0;
    map_flags |= 0x00000001; // speed normal
    map_flags |= 0x00000800; // visibility default?
    map_flags |= 0x00003000; // observers allowed
    
    unsigned int stat_string_tail = 0;
    memcpy(stat_string + stat_string_tail, 
           &map_flags, 
           sizeof(map_flags));
    stat_string_tail += sizeof(map_flags);
    stat_string_tail++; // null terminator.
    
    memcpy(stat_string + stat_string_tail, 
           &map->width, 
           sizeof(map->width));
    stat_string_tail += sizeof(map->width);
    
    memcpy(stat_string + stat_string_tail, 
           &map->height, 
           sizeof(map->height));
    stat_string_tail += sizeof(map->height);
    
    memcpy(stat_string + stat_string_tail, 
           &map->crc, 
           sizeof(map->crc));
    stat_string_tail += sizeof(map->crc);
    
    strcpy(stat_string + stat_string_tail, 
           map->path);
    stat_string_tail += strlen(map->path);
    stat_string_tail++; // null terminator.
    
    char host_name[] = "ruke";
    strcpy(stat_string + stat_string_tail, 
           host_name);
    stat_string_tail += strlen(host_name);
    stat_string_tail++; // null terminator.
    
    memcpy(stat_string + stat_string_tail, 
           map->sha1.digest.buf, 
           sizeof(map->sha1.digest.buf));
    stat_string_tail += sizeof(map->sha1.digest.buf);
    
    // encode stat string.
    unsigned char encoded_stat[512] = {0};
    unsigned char mask = 1;
    
    for (unsigned int i = 0; i < stat_string_tail; ++i) {
        // if ((stat_string[i] % 2) == 0)
        // ;
    }
    
    packet_write_size(dest);
}

void packet_server_sid_auth_check(struct packet *dest,
                                  unsigned int client_token,
                                  unsigned int exe_version,
                                  unsigned long exe_version_hash,
                                  struct key_info_roc *key_info_roc,
                                  struct key_info_tft *key_info_tft,
                                  struct exe_info *exe_info)
{
    assert(dest);
    assert(key_info_roc);
    assert(key_info_tft);
    
    unsigned char packet_type = 81;
    packet_write_header(dest, packet_type);
    
    packet_write_ex(dest, client_token);
    packet_write_ex(dest, exe_version);
    packet_write_ex(dest, exe_version_hash);
    
    unsigned int keys_count = 2;
    packet_write_ex(dest, keys_count);
    
    unsigned int spawn = 0;
    packet_write_ex(dest, spawn);
    
    packet_write_array(dest, key_info_roc->buf);
    packet_write_array(dest, key_info_tft->buf);
    packet_write_array(dest, exe_info->buf);
    
    char owner[] = "ruke";
    packet_write_array(dest, owner);
    
    packet_write_size(dest);
}

void packet_server_sid_auth_account_logon(struct packet *dest, 
                                          struct username *username,
                                          struct public_key *public_key)
{
    assert(dest);
    assert(username);
    assert(public_key);
    
    unsigned char packet_type = 0x53;
    packet_write_header(dest, packet_type);
    
    packet_write_array(dest, public_key->buf);
    packet_write_string(dest, username->buf);
    packet_write_size(dest);
}


void packet_server_sid_auth_account_logon_proof(struct packet *dest,
                                                struct hashed_password *hp)
{
    assert(dest);
    assert(hp);
    
    unsigned char packet_type = 0x54;
    packet_write_header(dest, packet_type);
    
    packet_write_array(dest, hp->buf);
    packet_write_size(dest);
}

void packet_server_sid_net_game_port(struct packet *dest, unsigned short port)
{
    assert(dest);
    unsigned char packet_type = 0x45;
    packet_write_header(dest, packet_type);
    packet_write_ex(dest, port);
    packet_write_size(dest);
}

void packet_server_sid_enter_chat(struct packet *dest)
{
    assert(dest);
    unsigned char packet_type = 0x0A;
    packet_write_header(dest, packet_type);
    packet_write_size(dest);
}

void packet_server_sid_join_channel(struct packet *dest, struct channel *channel)
{
    assert(dest);
    unsigned char packet_type = 0x0C;
    packet_write_header(dest, packet_type);
    unsigned int flags = 0x00; // no create join.
    packet_write_ex(dest, flags);
    packet_write_string(dest, channel->buf);
    packet_write_size(dest);
}
