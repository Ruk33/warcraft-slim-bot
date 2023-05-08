#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "include/packet.h"
#include "include/packet_server.h"
#include "include/bsha1.h"

struct server_name {
    char buf[256];
};

struct cd_key_roc {
    char buf[32]; // seems like the size is 26
};

struct cd_key_tft {
    char buf[32]; // seems like the size is 26
};

struct server_salt {
    unsigned char buf[32];
};

struct server_public_key {
    unsigned char buf[32];
};

struct conn {
    unsigned char read_buf[1024];
    int read_size;
};

int main(int argc, char **argv)
{
#define port 6112
#define server_address "127.0.0.1"
    
    if (argc != 3) {
        printf("%s <username> <password>\n", argv[0]);
        printf("example: %s my-bot-username my-bot-password\n", argv[0]);
        return 0;
    }
    
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, server_address, &address.sin_addr) <= 0) {
        printf("pton failed.\n");
        goto exit;
    }
    
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        printf("socket failed.\n");
        goto exit;
    }
    
    if (connect(client_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        printf("connect failed.\n");
        goto exit;
    }
    
    printf("seems like it's connected.\n");
    
    // send initial 1.
    unsigned char start = 1;
    send(client_fd, &start, sizeof(start), 0);
    
    // packets.
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
        printf("failed to send init packet.\n");
        goto exit;
    }
    printf("packet was sent. waiting for response.\n");
    
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
    
    exit:
    close(client_fd);
    printf("disconnecting and exiting.\n");
    return 0;
}