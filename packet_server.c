#include <assert.h>
#include <string.h> // strnlen
#include "include/packet.h"
#include "include/packet_server.h"
#include "include/bsha1.h"
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
    unsigned char product_id[] = {80, 88, 51, 87}; // "W3XP"
    unsigned char version_id[] = {29, 0, 0, 0};
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

void packet_server_account_login_proof(struct packet *dest, struct bsha1_password *password)
{
    assert(dest);
    
    unsigned char sid_auth_account_login_proof = 84;
    packet_write_header(dest, sid_auth_account_login_proof);
    
    struct bsha1_password hashed_password = {0};
    bsha1_hash_password(&hashed_password, password);
    
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

void packet_server_join_channel(struct packet *dest, struct channel_name *channel)
{
    assert(dest);
    assert(channel);
    
    unsigned char packet_type = 12;
    packet_write_header(dest, packet_type);
    
    int channel_len = (int) strnlen(channel->buf, sizeof(channel->buf));
    if (channel_len > 0) {
        unsigned char no_create_join[] = {2, 0, 0, 0};
        packet_write_array(dest, no_create_join);
    } else {
        unsigned char first_join[] = {1, 0, 0, 0};
        packet_write_array(dest, first_join);
    }
    if (channel_len) {
        // +1 null terminator.
        packet_write(dest, (unsigned char *) channel->buf, channel_len + 1);
    }
    packet_write_size(dest);
}

// note: should we change the weird name to something like
// start game, create game, or...?
void packet_server_start_adv_ex3(struct packet *dest)
{
    assert(dest);
    unsigned char packet_type = 28;
    packet_write_header(dest, packet_type);
    
    int game_state = (int) game_public;
    packet_write_ex(dest, game_state);
    
    int up_time = 0;
    packet_write_ex(dest, up_time);
    
    int game_map_type = game_map_type_unknown | game_map_type_melee;
    packet_write_ex(dest, game_map_type);
    
    int unknown = 0;
    packet_write_ex(dest, unknown);
    
    unsigned char custom_game[] = {0, 0, 0, 0};
    packet_write_array(dest, custom_game);
    
    char name[] = "testing!";
    packet_write_array(dest, name);
    
    unsigned char password = 0;
    packet_write_ex(dest ,password);
    
    unsigned char slots_free = 110;
    packet_write_ex(dest, slots_free);
    
    // check what am i supposed to send here.
    char host_counter[] = "00000000";
    packet_write(dest, (unsigned char *) host_counter, sizeof(host_counter) - 1);
    
    int stat_start = dest->size;
    
    unsigned char map_flags = 1;
    packet_write_ex(dest, map_flags);
    
    unsigned char empty = 0;
    packet_write_ex(dest, empty);
    
    unsigned char map_width = 128;
    packet_write_ex(dest, map_width);
    
    unsigned char map_height = 96;
    packet_write_ex(dest, map_height);
    
    unsigned char map_crc = 0;
    packet_write_ex(dest, map_crc);
    
    char map_path[] = "./(2)EchoIsles.w3x";
    packet_write_array(dest, map_path);
    
    char host_name[] = "testruke";
    packet_write_array(dest, host_name);
    
    packet_write_ex(dest, empty);
    
    // echo isles sha1.
    char sha1[] = "a98ac683c62bd3d45e1c43535ca75f6599aa60cf";
    packet_write_array(dest, sha1);
    
    // encode stat string.
    unsigned char mask = 1;
    int size = dest->size;
    for (int i = stat_start; i < size; i++) {
        if (dest->buf[i] % 2 == 0) {
            dest->buf[i] = dest->buf[i] + 1;
        } else {
            mask |= 1 << (((i - stat_start) % 7) + 1);
        }
        if ((i - stat_start) % 7 == 6 || i == size - 1) {
            // manually add mask. double check since this is
            // probably wrong.
            int index = size - 1 - ((i - stat_start) % 7);
            unsigned char tmp = dest->buf[index];
            dest->buf[index] = mask;
            dest->buf[index + 1] = tmp;
            dest->size++;
            mask = 1;
        }
    }
    // null terminator from stat "string".
    packet_write_ex(dest, empty);
    
    packet_write_size(dest);
}
