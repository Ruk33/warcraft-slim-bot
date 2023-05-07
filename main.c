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
    
    // send init packet.
    struct packet init = {0};
    packet_server_init(&init);
    if (send(client_fd, init.buf, init.size, 0) != init.size) {
        printf("failed to send inital 1.\n");
        goto exit;
    }
    printf("packet was sent. waiting for response.\n");
    
    // start of checking if "keys" are valid.
    struct packet response = {0};
    response.size = (int) recv(client_fd, response.buf, sizeof(response.buf), 0);
    printf("packets were read!\n");
    // printf("first byte is correct? %d\n", response.buf[0] == bnet_header);
    printf("packet type is %d\n", (int)response.buf[1]);
    
    unsigned char sid_auth_check = 81;
    if (response.buf[1] != sid_auth_check) {
        printf("expecting %d but got %d", sid_auth_check, response.buf[1]);
        goto exit;
    }
    
    printf("checking if the keys are valid.\n");
    int key_state = 0;
    memcpy(&key_state, response.buf + 4, sizeof(key_state));
    printf("key_state is %d.\n", key_state);
    if (key_state != 0) {
        printf("key state failed.\n");
        goto exit;
    }
    
    // send account logon.
    struct packet account_logon = {0};
    packet_server_account_logon(&account_logon);
    if (send(client_fd, account_logon.buf, account_logon.size, 0) != account_logon.size) {
        printf("failed to send account logon.\n");
        goto exit;
    }
    
    printf("account logon sent!\n");
    response.size = (int) recv(client_fd, response.buf, sizeof(response.buf), 0);
    // printf("packet is correct %d\n", (int)response.buf[0] == bnet_header);
    printf("packet type is %d\n", (int)response.buf[1]);
    
    // check if username was accepted.
    if (response.buf[1] != 83) {
        printf("expected 83.\n");
        goto exit;
    }
    
    struct server_salt salt = {0};
    struct server_public_key public_key = {0};
    memcpy(salt.buf, response.buf + 8, sizeof(salt.buf));
    memcpy(public_key.buf, response.buf + 40, sizeof(public_key.buf));
    
    struct packet login_proof = {0};
    packet_server_account_login_proof(&login_proof);
    if (send(client_fd, login_proof.buf, login_proof.size, 0) != login_proof.size) {
        printf("failed to send account login proof.\n");
        goto exit;
    }
    
    response.size = (int) recv(client_fd, response.buf, sizeof(response.buf), 0);
    // printf("packet is correct %d\n", (int)response.buf[0] == bnet_header);
    printf("checking if password was accepted.\n");
    printf("packet type is %d\n", (int)response.buf[1]);
    
    int password_status = 0;
    memcpy(&password_status, response.buf + 4, sizeof(password_status));
    printf("pass ok? %s\n", password_status == 0 || password_status == 0xE ? "yes" : "no");
    
    exit:
    close(client_fd);
    printf("disconnecting and exiting.\n");
    return 0;
}