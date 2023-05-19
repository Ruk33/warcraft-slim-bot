#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bncsutil/bncsutil.h>

#include "include/packet.h"
#include "include/packet_server.h"
#include "include/bsha1.h"

struct server_name {
    char buf[256];
};

struct server_salt {
    unsigned char buf[32];
};

struct server_public_key {
    unsigned char buf[32];
};

struct ver_file_name {
    char buf[15];
};

struct value_string_formula {
    char buf[63];
};

struct conn {
    unsigned int logon_type;
    unsigned int server_token;
    unsigned int udp_value;
    unsigned long long mpq_file_time;
    struct ver_file_name ver_file_name;
    struct value_string_formula value_string_formula;
    unsigned int client_token;
    unsigned int public_value;
    unsigned int product;
    unsigned int exe_version;
    unsigned long exe_version_hash;
    struct cd_key_roc cd_key_roc;
    struct cd_key_tft cd_key_tft;
    struct key_info_roc key_info_roc;
    struct key_info_tft key_info_tft;
};

#define packet_read_value(dest, packet, head) \
    (memcpy(&(dest), (packet)->buf + 4 + *(head), sizeof(dest)), *(head) += sizeof(dest))

// +1 null terminator.
#define packet_read_string(dest, packet, head) \
    (strncpy((dest), (char *) ((packet)->buf + 4 + *(head)), sizeof(dest) - 1), *(head) += strlen(dest) + 1)

static void read_packet(struct packet *dest, int client_fd)
{
    // 1 constant 0xff
    // 1 packet type
    // 2 packet size
    printf("INF / waiting for packet from client...\n");

    dest->size = (int) recv(client_fd, dest->buf, 4, 0);
    assert(dest->size == 4 && "minimum of 4 bytes per packet.");
    assert(dest->buf[0] == 0xff && "first byte isnt correct.");

    unsigned short packet_size = 0;
    memcpy(&packet_size, dest->buf + 2, sizeof(packet_size));

    dest->size += (int) recv(client_fd, dest->buf + 4, packet_size - 4, 0);
    assert(dest->size == packet_size);

    printf(" OK / packet from client correct, type is %#04x...\n", dest->buf[1]);

    // todo, dont read more than buf capacity
    // todo, check that recv doesnt return -1 
}

static int send_packet(int client_fd, struct packet *src, char *packet_name)
{
    assert(src);
    assert(packet_name);

    printf("INF / trying to send '%s'...\n", packet_name);
    if (send(client_fd, src->buf, src->size, 0) != src->size) {
        printf("ERR / failed to send '%s'...\n", packet_name);
        return 0;
    }

    printf(" OK / packet '%s' was sent...\n", packet_name);
    return 1;
}

int main(int argc, char **argv)
{
#define port 6112
#define server_address "127.0.0.1"

    char war[] = "/mnt/c/Users/franc/Downloads/Warcraft III 1.27/war3.exe";
    char storm_dll[] = "/mnt/c/Users/franc/Downloads/Warcraft III 1.27/Storm.dll";
    char game_dll[] = "/mnt/c/Users/franc/Downloads/Warcraft III 1.27/game.dll";
    struct exe_info exe_info = {0};
    unsigned int exe_version = 0;

    getExeInfo(war, exe_info.buf, sizeof(exe_info.buf), &exe_version, BNCSUTIL_PLATFORM_X86);
    printf("INF / buf is: '%s', exe_version: %d\n", exe_info.buf, exe_version);
    
    if (argc != 5) {
        printf("%s <username> <password> <roc key> <tft key>\n", argv[0]);
        printf("example: %s my-bot-username my-bot-password roc-key-without-hypens tft-without-hyphens\n", argv[0]);
        return 0;
    }
    
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, server_address, &address.sin_addr) <= 0) {
        printf("ERR / pton failed.\n");
        goto exit;
    }
    
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        printf("ERR / socket failed.\n");
        goto exit;
    }
    
    if (connect(client_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        printf("ERR / connect failed.\n");
        goto exit;
    }
    
    printf("INF / seems like it's connected.\n");
    
    // send initial 1.
    unsigned char start = 1;
    send(client_fd, &start, sizeof(start), 0);
    
    // packets.
    static struct conn conn = {0};
    struct packet to_client = {0};
    struct packet from_client = {0};
    
    // auth.
    struct username username = {0};
    struct bsha1_password password = {0};
    strncpy(username.buf, argv[1], sizeof(username.buf) - 1);
    strncpy(password.buf, argv[2], sizeof(password.buf) - 1);
    
    // send init packet.
    to_client.size = 0;
    packet_server_init(&to_client);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("ERR / failed to send init packet.\n");
        goto exit;
    }
    printf("INF / packet was sent. waiting for response.\n");
    
    while (1) {
        read_packet(&from_client, client_fd);

        switch (from_client.buf[1]) {

        case 0x25: // ping
        unsigned int ping = 0;
        memcpy(&ping, from_client.buf + 4, sizeof(ping));
        printf("ping %d\n", ping);

        to_client.size = 0;
        packet_server_ping(&to_client, ping);
        if (!send_packet(client_fd, &to_client, "ping")) {
            printf("failed to send ping.\n");
            goto exit;
        }
        break;

        case 0x50: // auth info
        int head = 0;
        packet_read_value(conn.logon_type, &from_client, &head);
        packet_read_value(conn.server_token, &from_client, &head);
        packet_read_value(conn.udp_value, &from_client, &head);
        packet_read_value(conn.mpq_file_time, &from_client, &head);
        packet_read_string(conn.ver_file_name.buf, &from_client, &head);
        packet_read_string(conn.value_string_formula.buf, &from_client, &head);
        checkRevisionFlat(conn.value_string_formula.buf,
                          war,
                          storm_dll,
                          game_dll,
                          extractMPQNumber(conn.ver_file_name.buf),
                          &conn.exe_version_hash);

        unsigned char client_token_raw[] = {220, 1, 203, 7};
        memcpy(&conn.client_token, client_token_raw, sizeof(conn.client_token));
        strncpy(conn.cd_key_roc.buf, argv[3], sizeof(conn.cd_key_roc.buf) - 1);
        strncpy(conn.cd_key_tft.buf, argv[4], sizeof(conn.cd_key_tft.buf) - 1);

        int key_result = 0;
        key_result = kd_quick(conn.cd_key_roc.buf, 
                              conn.client_token, 
                              conn.server_token, 
                              &conn.public_value, 
                              &conn.product, 
                              conn.key_info_roc.buf, 
                              sizeof(conn.key_info_roc.buf));
        printf("INF / roc key info > %d\n", key_result);

        key_result = kd_quick(conn.cd_key_tft.buf, 
                              conn.client_token, 
                              conn.server_token, 
                              &conn.public_value, 
                              &conn.product, 
                              conn.key_info_tft.buf, 
                              sizeof(conn.key_info_tft.buf));
        printf("INF / tft key info > %d\n", key_result);

        to_client.size = 0;
        packet_server_sid_auth_check(&to_client,
                                     conn.client_token,
                                     exe_version,
                                     conn.exe_version_hash,
                                     &conn.key_info_roc,
                                     &conn.key_info_tft,
                                     &exe_info);
        if (!send_packet(client_fd, &to_client, "sid auth check"))
            goto exit;
        break;

        case 0x51: {
            int head = 0;
            unsigned int key_status = 0;
            packet_read_value(key_status, &from_client, &head);

            char description[256] = {0};
            packet_read_string(description, &from_client, &head);
            memcpy(&key_status, from_client.buf + 4, sizeof(key_status));
            printf("key status is %d / '%s'.\n", key_status, description);
        } break;

        default:
        printf("unknown packet received %d.\n", from_client.buf[1]);
        goto exit;
        break;
        }
    }

#if 0
    // start of checking if "keys" are valid.
    from_client.size = (int) recv(client_fd, from_client.buf, sizeof(from_client.buf), 0);
    printf("packets were read!\n");
    // printf("first byte is correct? %d\n", response.buf[0] == bnet_header);
    printf("packet type is %d\n", (int)from_client.buf[1]);
    
    // ping.
    if (from_client.buf[1] != 37) {
        printf("expecting ping.\n");
        goto exit;
    }
    
    // int max = 0;
    // while (from_client.buf[1] == 37 && max++ < 1) {
    int ping = 0;
    memcpy(&ping, from_client.buf + 4, sizeof(ping));
    printf("ping was %d.\n", ping);
    
    // send back ping.
    to_client.size = 0;
    packet_server_ping(&to_client, ping);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to send ping.\n");
        goto exit;
    }
    from_client.size = (int) recv(client_fd, from_client.buf, sizeof(from_client.buf), 0);
    // }
    
    // check keys.
    char logon_type[4] = {0};
    char server_token[4] = {0};
    char mpq_file_time[8] = {0};
    char ver_file_name[256] = {0};
    char value_string_formula[256] = {0};
    memcpy(logon_type, from_client.buf + 4, sizeof(logon_type));
    memcpy(server_token, from_client.buf + 8, sizeof(server_token));
    memcpy(mpq_file_time, from_client.buf + 16, sizeof(mpq_file_time));
    strncpy(ver_file_name, (char *) (from_client.buf + 24), sizeof(ver_file_name) - 1);
    // +1 null terminator.
    int ver_file_name_size = strnlen(ver_file_name, sizeof(ver_file_name)) + 1;
    strncpy(value_string_formula, (char *) (from_client.buf + 25 + ver_file_name_size), sizeof(value_string_formula) - 1);
    printf("file_name %s, value_string %s\n", ver_file_name, value_string_formula);
    
    unsigned long exe_version_hash = 0;
    checkRevisionFlat(value_string_formula,
                      war,
                      storm_dll,
                      game_dll,
                      extractMPQNumber(ver_file_name),
                      &exe_version_hash);
    
    unsigned char client_token_raw[] = {220, 1, 203, 7};
    unsigned int client_token = 0;
    unsigned int server_token2 = 0;
    unsigned int public_value = 0;
    unsigned int product = 0;
    char hash_buf[1024] = {0};
    memcpy(&client_token, client_token_raw, sizeof(client_token));
    memcpy(&server_token2, server_token, sizeof(server_token2));
    // int key_type = 3; // KEY_WARCRAFT3;
    char cd_key[] = "warcraft-3-key-without-hyphen";
    int q = kd_quick(cd_key, client_token, server_token2, &public_value, &product, hash_buf, sizeof(hash_buf));
    
    printf("kd_quick success: %d\n", q);
    
    unsigned char sid_auth_check = 81;
    if (from_client.buf[1] != sid_auth_check) {
        printf("expecting %d but got %d", sid_auth_check, from_client.buf[1]);
        goto exit;
    }
    
    printf("checking if the keys are valid.\n");
    int key_state = 0;
    memcpy(&key_state, from_client.buf + 4, sizeof(key_state));
    printf("key_state is %d.\n", key_state);
    if (key_state != 0) {
        printf("key state failed.\n");
        goto exit;
    }
    
    // send account logon.
    to_client.size = 0;
    packet_server_account_logon(&to_client, &username);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to send account logon.\n");
        goto exit;
    }
    
    printf("account logon sent!\n");
    from_client.size = (int) recv(client_fd, from_client.buf, sizeof(from_client.buf), 0);
    // printf("packet is correct %d\n", (int)response.buf[0] == bnet_header);
    printf("packet type is %d\n", (int)from_client.buf[1]);
    
    // check if username was accepted.
    if (from_client.buf[1] != 83) {
        printf("expected 83.\n");
        goto exit;
    }
    
    struct server_salt salt = {0};
    struct server_public_key public_key = {0};
    memcpy(salt.buf, from_client.buf + 8, sizeof(salt.buf));
    memcpy(public_key.buf, from_client.buf + 40, sizeof(public_key.buf));
    
    to_client.size = 0;
    packet_server_account_login_proof(&to_client, &password);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to send account login proof.\n");
        goto exit;
    }
    
    from_client.size = (int) recv(client_fd, from_client.buf, sizeof(from_client.buf), 0);
    // printf("packet is correct %d\n", (int)response.buf[0] == bnet_header);
    printf("checking if password was accepted.\n");
    printf("packet type is %d\n", (int)from_client.buf[1]);
    
    int password_status = 0;
    memcpy(&password_status, from_client.buf + 4, sizeof(password_status));
    
    int password_ok = password_status == 0 || password_status == 0xE;
    printf("pass ok? %s\n", password_ok ? "yes" : "no");
    
    if (!password_ok) {
        printf("password invalid.\n");
        goto exit;
    }
    
    to_client.size = 0;
    packet_server_net_game_port(&to_client);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to send net game port.\n");
        goto exit;
    }
    
    to_client.size = 0;
    packet_server_enter_chat(&to_client);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to send enter chat.\n");
        goto exit;
    }
    
    to_client.size = 0;
    packet_server_friend_list(&to_client);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to send friend list.\n");
        goto exit;
    }
    
    to_client.size = 0;
    packet_server_clan_member_list(&to_client);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to send clan member list.\n");
        goto exit;
    }
    
    printf("all was sent.\n");
    
    from_client.size = (int) recv(client_fd, from_client.buf, sizeof(from_client.buf), 0);
    // printf("packet is correct %d\n", (int)response.buf[0] == bnet_header);
    printf("packet type is %d\n", (int)from_client.buf[1]);
    
    // enter chat response.
    if (from_client.buf[1] != 10) {
        printf("expected 10.\n");
        goto exit;
    }
    
    struct channel_name channel_name = {0};
    strncpy(channel_name.buf, (char *) (from_client.buf + 4), sizeof(channel_name.buf) - 1);
    
    printf("channel: %s.\n", channel_name.buf);
    
    struct channel_name channel_to_join = {"Warcraft 3 Frozen Throne"};
    to_client.size = 0;
    packet_server_join_channel(&to_client, &channel_to_join);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to send join channel.\n");
        goto exit;
    }
    
#if 0
    // create game.
    to_client.size = 0;
    packet_server_start_adv_ex3(&to_client);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to create game.\n");
        goto exit;
    }
#endif
    
    // friend list (101).
    from_client.size = (int) recv(client_fd, from_client.buf, sizeof(from_client.buf), 0);
    // printf("packet is correct %d\n", (int)response.buf[0] == bnet_header);
    printf("packet type is %d\n", (int)from_client.buf[1]);
    
    // chat event (15).
    from_client.size = (int) recv(client_fd, from_client.buf, sizeof(from_client.buf), 0);
    printf("packet type is %d\n", (int)from_client.buf[1]);
    
    // create game.
    to_client.size = 0;
    packet_server_start_adv_ex3(&to_client);
    if (send(client_fd, to_client.buf, to_client.size, 0) != to_client.size) {
        printf("failed to create game.\n");
        goto exit;
    }
    
    // start dvex3 (28)
    from_client.size = (int) recv(client_fd, from_client.buf, sizeof(from_client.buf), 0);
    printf("packet type is %d\n", (int)from_client.buf[1]);
    
    unsigned int create_game_status = 0;
    memcpy(&create_game_status, from_client.buf + 4, sizeof(create_game_status));
    printf("create game status:%d if 0 then ok.\n", create_game_status);
    
    sleep(30);
#endif
    
    exit:
    close(client_fd);
    printf("disconnecting and exiting.\n");
    return 0;
}