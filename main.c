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

struct server_name {
    char buf[256];
};

struct cd_key_roc {
    char buf[32]; // seems like the size is 26
};

struct cd_key_tft {
    char buf[32]; // seems like the size is 26
};

struct username {
    char buf[64];
};

struct password {
    char buf[32]; // 20 is max.
};

struct server_salt {
    unsigned char buf[32];
};

struct server_public_key {
    unsigned char buf[32];
};

int main(void)
{
#define port 6112
#define server_address "127.0.0.1"
    
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
    packet_server_account_logon(&to_client);
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
    packet_server_account_login_proof(&to_client);
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
    
    exit:
    close(client_fd);
    printf("disconnecting and exiting.\n");
    return 0;
}