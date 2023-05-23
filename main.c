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
#include <StormLib.h>

#include "include/packet.h"
#include "include/packet_server.h"
#include "include/crc32.h"

struct server_name {
    char buf[256];
};

struct server_salt {
    unsigned char buf[32];
};

struct ver_file_name {
    char buf[15];
};

struct value_string_formula {
    char buf[63];
};

// 128 mb in 1.27b
#define max_map_size_in_byes (128000000)

struct map {
    unsigned char buf[max_map_size_in_byes];
    long size;
    unsigned int crc;
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
    struct salt salt;
    struct server_key server_key;
    struct map map;
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
    char maps[] = "/mnt/c/Users/franc/Downloads/Warcraft III 1.27/Maps/FrozenThrone/";
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
    struct password password = {0};
    strncpy(username.buf, argv[1], sizeof(username.buf) - 1);
    strncpy(password.buf, argv[2], sizeof(password.buf) - 1);
    strncpy(conn.cd_key_roc.buf, argv[3], sizeof(conn.cd_key_roc.buf) - 1);
    strncpy(conn.cd_key_tft.buf, argv[4], sizeof(conn.cd_key_tft.buf) - 1);

    unsigned char client_token_raw[] = {220, 1, 203, 7};
    memcpy(&conn.client_token, client_token_raw, sizeof(conn.client_token));

    // yes, this allocates memory but since it's only done
    // once, let the operating system take care of it.
    nls_t *nls = nls_init(username.buf, password.buf);
    if (!nls) {
        printf("ERR / unable to init nls.\n");
        goto exit;
    }

    struct public_key public_key = {0};
    nls_get_A(nls, public_key.buf);

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

        // ping.
        case 0x25: {
            unsigned int ping = 0;
            memcpy(&ping, from_client.buf + 4, sizeof(ping));
            printf("INF / ping %d\n", ping);

            to_client.size = 0;
            packet_server_ping(&to_client, ping);
            if (!send_packet(client_fd, &to_client, "ping"))
                goto exit;
        } break;

        // auth info
        case 0x50: {
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
        } break;

        // sid auth check.
        case 0x51: {
            int tmp = 0;
            unsigned int key_status = 0;
            packet_read_value(key_status, &from_client, &tmp);
            memcpy(&key_status, from_client.buf + 4, sizeof(key_status));
            printf("INF / key status is %d.\n", key_status);
            if (key_status != 0) {
                printf("ERR / keys were not accepted.\n");
                goto exit;
            }

            // sid auth account logon
            to_client.size = 0;
            packet_server_sid_auth_account_logon(&to_client, &username, &public_key);
            if (!send_packet(client_fd, &to_client, "sid auth account logon"))
                goto exit;
        } break;

        // sid auth account logon.
        case 0x53: {
            int head = 0;
            unsigned int status = 0;
            packet_read_value(status, &from_client, &head);
            if (status != 0) {
                printf("ERR / username seems to be incorrect %d.\n", status);
                goto exit;
            }
            packet_read_value(conn.salt.buf, &from_client, &head);
            packet_read_value(conn.server_key.buf, &from_client, &head);

            struct hashed_password hp = {0};
            hashPassword(password.buf, hp.buf);

            to_client.size = 0;
            packet_server_sid_auth_account_logon_proof(&to_client, &hp);
            if (!send_packet(client_fd, &to_client, "sid auth account logon proof"))
                goto exit;
        } break;

        // sid account logon proof.
        case 0x54: {
            int head = 0;
            unsigned int status = 0;
            packet_read_value(status, &from_client, &head);
            if (status != 0) {
                printf("ERR / password is incorrect.\n");
                goto exit;
            }

            // net game port
            // defines which port will the bot use for hosting games.
            to_client.size = 0;
            packet_server_sid_net_game_port(&to_client, 6113);
            if (!send_packet(client_fd, &to_client, "sid net game port"))
                goto exit;
            // enter chat
            to_client.size = 0;
            packet_server_sid_enter_chat(&to_client);
            if (!send_packet(client_fd, &to_client, "sid enter chat"))
                goto exit;
            // join channel.
            struct channel to_join = {"Warcraft 3 Frozen Throne"};
            to_client.size = 0;
            packet_server_sid_join_channel(&to_client, &to_join);
            if (!send_packet(client_fd, &to_client, "sid join channel"))
                goto exit;

            // create a game.

            char map_path[128] = {0};
            snprintf(map_path, sizeof(map_path) - 1, "%s/(2)EchoIsles.w3x", maps);

            // load map file.
            FILE *map_file = fopen(map_path, "rb");
            if (!map_file) {
                printf("ERR / unable to read %s.\n", map_path);
                goto exit;
            }
            
            fseek(map_file, 0, SEEK_END);
            conn.map.size = ftell(map_file);
            fseek(map_file, 0, SEEK_SET);
            if (conn.map.size > max_map_size_in_byes) {
                printf("ERR / the map seems to be bigger than what's supported in 1.27b.\n");
                goto exit;
            }

            fread(conn.map.buf, 1, conn.map.size, map_file);
            fclose(map_file);

            // load map mpq
            HANDLE map_mpq = 0;
            if (!SFileOpenArchive(map_path, 0, MPQ_OPEN_FORCE_MPQ_V1, &map_mpq)) {
                printf("ERR / unable to load mpq of %s.\n", map_path);
                goto exit;
            }

            conn.map.crc = crc_full(conn.map.buf, (unsigned int) conn.map.size);
        } break;

        default: {
            printf("ERR / the packet wont be handled, ignoring...\n");
            // goto exit;
        } break;
        }
    }

    exit:
    close(client_fd);
    printf("disconnecting and exiting.\n");
    return 0;
}