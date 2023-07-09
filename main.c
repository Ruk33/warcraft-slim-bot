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

#include "include/types.h"
#include "include/packet.h"
#include "include/packet_server.h"
#include "include/crc32.h"
#include "include/sha1.h"

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

#define mpq_read_value(dest, mpq, head) \
(memcpy(&(dest), (mpq) + *(head), sizeof(dest)), *(head) += sizeof(dest))

// +1 null terminator.
#define mpq_read_string(dest, mpq, head) \
(strncpy((dest), (char *) ((mpq) + *(head)), sizeof(dest) - 1), *(head) += strlen(dest) + 1)

// won't work with signed types.
#define ROTL(x,n) ((x)<<(n))|((x)>>(32-(n)))

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

static int read_file(unsigned char *dest, long dest_size, char *path, long *size)
{
    assert(dest);
    assert(path);
    assert(size);
    
    FILE *file = fopen(path, "rb");
    if (!file)
        return 0;
    
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (*size > dest_size)
        return 0;
    
    fread(dest, 1, *size, file);
    fclose(file);
    return 1;
}

static unsigned int xor_rotate_left(unsigned char *data, unsigned int length)
{
    assert(data);
    
    unsigned int i = 0;
    unsigned int val = 0;
    
    if (length > 3) {
        while (i < length - 3) {
            val = ROTL(val ^ ((unsigned int) data[i] + (unsigned int) (data[i + 1] << 8) + (unsigned int) (data[i + 2] << 16) + (unsigned int) (data[i + 3] << 24)), 3);
            i += 4;
        }
    }
    
    while (i < length) {
        val = ROTL(val ^ data[i], 3);
        ++i;
    }
    
    return val;
}

int main(int argc, char **argv)
{
#define port 6112
#define server_address "127.0.0.1"
    
    char war[] = "/home/franco/Downloads/Warcraft III 1.27/war3.exe";
    char storm_dll[] = "/home/franco/Downloads/Warcraft III 1.27/Storm.dll";
    char game_dll[] = "/home/franco/Downloads/Warcraft III 1.27/game.dll";
    char maps[] = "/home/franco/Downloads/Warcraft III 1.27/Maps/FrozenThrone/";
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
                unsigned int head = 0;
                unsigned int ping = 0;
                packet_read_value(ping, &from_client, &head);
                printf("INF / ping %u\n", ping);
                
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
                // char map_path[128] = {0};
                snprintf(conn.map.path,
                         sizeof(conn.map.path) - 1,
                         "%s/(2)EchoIsles.w3x", maps);
                
                // load map file.
                if (!read_file(conn.map.buf, sizeof(conn.map.buf), conn.map.path, &conn.map.size)) {
                    printf("ERR / unable to read map %s.\n", conn.map.path);
                    goto exit;
                }
                
                // load map mpq
                HANDLE map_mpq = 0;
                if (!SFileOpenArchive(conn.map.path, 0, MPQ_OPEN_FORCE_MPQ_V1, &map_mpq)) {
                    printf("ERR / unable to load mpq of %s.\n", conn.map.path);
                    goto exit;
                }
                
                conn.map.crc = crc_full(conn.map.buf, (unsigned int) conn.map.size);
                
                char commonj_path[] = "/home/franco/Downloads/common.j";
                if (!read_file(conn.map.commonj.buf, sizeof(conn.map.commonj.buf), commonj_path, &conn.map.commonj.size)) {
                    printf("ERR / unable to read common.j\n");
                    goto exit;
                }
                
                char blizzardj_path[] = "/home/franco/Downloads/Blizzard.j";
                if (!read_file(conn.map.blizzardj.buf, sizeof(conn.map.blizzardj.buf), blizzardj_path, &conn.map.blizzardj.size)) {
                    printf("ERR / unable to read blizzard.j\n");
                    goto exit;
                }
                
                // map crc
                unsigned int value = 0;
                
                value = value ^ xor_rotate_left(conn.map.commonj.buf, conn.map.commonj.size);
                // sha1 update
                sha1_update(&conn.map.sha1,
                            conn.map.commonj.buf,
                            conn.map.commonj.size);
                
                value = value ^ xor_rotate_left(conn.map.blizzardj.buf, conn.map.blizzardj.size);
                // sha1 update
                sha1_update(&conn.map.sha1,
                            conn.map.blizzardj.buf,
                            conn.map.blizzardj.size);
                
                value = ROTL(value, 3);
                value = ROTL(value ^ 0x03F1379E, 3);
                // sha1 update, (uint8_t *) "\x9E\x37\xF1\x03", 4
                sha1_update(&conn.map.sha1,
                            (unsigned char *) "\x9E\x37\xF1\x0",
                            4);
                
                char *files_in_mpq[] = {
                    "war3map.j",
                    "scripts\\war3map.j",
                    "war3map.w3e",
                    "war3map.wpm",
                    "war3map.doo",
                    "war3map.w3u",
                    "war3map.w3b",
                    "war3map.w3d",
                    "war3map.w3a",
                    "war3map.w3q",
                    0,
                };
                // int found_script = 0;
                
                for (char **file_in_mpq = files_in_mpq; *file_in_mpq; file_in_mpq++) {
                    // 1mb for these internal files should be more than enough.
                    static unsigned char buf[1024000] = {0};
                    
                    printf("INF / trying to read file in mpq %s.\n", *file_in_mpq);
                    
                    HANDLE mpq = 0;
                    if (!SFileOpenFileEx(map_mpq, *file_in_mpq, 0, &mpq)) {
                        printf("INF / unable to open %s from map mpq."
                               "maybe the file does not exist in the map.\n", 
                               *file_in_mpq);
                        continue;
                    }
                    
                    unsigned int size = SFileGetFileSize(mpq, 0);
                    if (size > sizeof(buf)) {
                        printf("ERR / %s seems to be way to big. this should not happen!\n", *file_in_mpq);
                        goto exit;
                    }
                    
                    DWORD bytes_read = 0;
                    if (!SFileReadFile(mpq, buf, size, &bytes_read, 0)) {
                        printf("ERR / unable to read contents of %s from mpq.\n", *file_in_mpq);
                        goto exit;
                    }
                    
                    value = ROTL(value ^ xor_rotate_left(buf, bytes_read), 3);
                    conn.map.crc = value;
                    
                    // sha update...
                    sha1_update(&conn.map.sha1,
                                buf,
                                bytes_read);
                    
                    SFileCloseFile(mpq);
                    printf(" OK / file %s was read successfuly.\n", *file_in_mpq);
                }
                
                {
                    // todo: confirm if this is big enough.
                    static unsigned char buf[1024000] = {0};
                    
                    HANDLE mpq = 0;
                    
                    if (!SFileOpenFileEx(map_mpq, "war3map.w3i", 0, &mpq)) {
                        printf("ERR / unable to read war3map.w3i.\n");
                        goto exit;
                    }
                    
                    unsigned int size = SFileGetFileSize(mpq, 0);
                    if (size > sizeof(buf)) {
                        printf("ERR / war3map.w3i seems to be way to big. this should not happen!\n");
                        goto exit;
                    }
                    
                    DWORD bytes_read = 0;
                    if (!SFileReadFile(mpq, buf, size, &bytes_read, 0)) {
                        printf("ERR / unable to read contents of war3map.w3i from mpq.\n");
                        goto exit;
                    }
                    
                    unsigned int head = 0;
                    
                    unsigned int format = 0;
                    mpq_read_value(format, buf, &head);
                    printf("INF / format is %u\n", format);
                    
                    unsigned int number_saves = 0;
                    mpq_read_value(number_saves, buf, &head);
                    printf("INF / number saves is %u\n", number_saves);
                    
                    unsigned int editor_version = 0;
                    mpq_read_value(editor_version, buf, &head);
                    printf("INF / editor version is %u\n", editor_version);
                    
                    char map_name[256] = {0};
                    mpq_read_string(map_name, buf, &head);
                    printf("INF / map name is %s\n", map_name);
                    
                    char map_author[256] = {0};
                    mpq_read_string(map_author, buf, &head);
                    printf("INF / map author is %s\n", map_author);
                    
                    char map_description[256] = {0};
                    mpq_read_string(map_description, buf, &head);
                    printf("INF / map description is %s\n", map_description);
                    
                    char players_recommended[256] = {0};
                    mpq_read_string(players_recommended, buf, &head);
                    printf("INF / players recommended is %s\n", players_recommended);
                    
                    head += 32; // skip camera bounds.
                    head += 16; // skip camera bounds complements.
                    
                    unsigned width = 0;
                    mpq_read_value(width, buf, &head);
                    conn.map.width = width;
                    printf("INF / width is %u\n", width);
                    
                    unsigned height = 0;
                    mpq_read_value(height, buf, &head);
                    conn.map.height = height;
                    printf("INF / height is %u\n", height);
                    
                    unsigned flags = 0;
                    mpq_read_value(flags, buf, &head);
                    printf("INF / flags is %u\n", flags);
                    
                    head += 1; // skip map main ground type.
                    head += 4; // skip campaing background number if format == 18, if format == 25 loading screen number.
                    
                    if (format == 25) {
                        char loading_screen[256] = {0};
                        mpq_read_string(loading_screen, buf, &head);
                        printf("INF / loading screen is %s\n", loading_screen);
                    }
                    
                    char loading_screen_text[256] = {0};
                    mpq_read_string(loading_screen_text, buf, &head);
                    printf("INF / loading screen text is %s\n", loading_screen_text);
                    
                    char loading_screen_title[256] = {0};
                    mpq_read_string(loading_screen_title, buf, &head);
                    printf("INF / loading screen title is %s\n", loading_screen_title);
                    
                    char loading_screen_subtitle[256] = {0};
                    mpq_read_string(loading_screen_subtitle, buf, &head);
                    printf("INF / loading screen subtitle is %s\n", loading_screen_subtitle);
                    
                    head += 4; // skip map loading screen if format == 18, otherwise, user game data set.
                    
                    if (format == 25) {
                        char prologue_screen_path[256] = {0};
                        mpq_read_string(prologue_screen_path, buf, &head);
                        printf("INF / prologue screen path is %s\n", prologue_screen_path);
                    }
                    
                    char prologue_screen_text[256] = {0};
                    mpq_read_string(prologue_screen_text, buf, &head);
                    printf("INF / prologue screen text is %s\n", prologue_screen_text);
                    
                    char prologue_screen_title[256] = {0};
                    mpq_read_string(prologue_screen_title, buf, &head);
                    printf("INF / prologue screen title is %s\n", prologue_screen_title);
                    
                    char prologue_screen_subtitle[256] = {0};
                    mpq_read_string(prologue_screen_subtitle, buf, &head);
                    printf("INF / prologue screen subtitle is %s\n", prologue_screen_subtitle);
                    
                    if (format == 25) {
                        head += 4; // terrain fog
                        head += 4; // fog start z height
                        head += 4; // fog end z height
                        head += 4; // fog density
                        head += 1; // fog red value
                        head += 1; // fog green value
                        head += 1; // fog blue value
                        head += 1; // fog alpha value
                        head += 4; // global weather id
                        
                        char sound_environment[256] = {0};
                        mpq_read_string(sound_environment, buf, &head);
                        
                        head += 1; // tileset id
                        head += 1; // custom water red
                        head += 1; // custom water green
                        head += 1; // custom water blue
                        head += 1; // custom water alpha
                    }
                    
                    unsigned int number_players = 0;
                    mpq_read_value(number_players, buf, &head);
                    printf("INF / numberplayers is %u\n", number_players);
                    
                    for (unsigned int i = 0; i < number_players; i++) {
                        unsigned int color = 0;
                        mpq_read_value(color, buf, &head);
                        printf("INF / player %d - color is %u\n", i + 1, color);
                        
                        unsigned int status = 0;
                        mpq_read_value(status, buf, &head);
                        printf("INF / player %d - status is %u\n", i + 1, status);
                        
                        unsigned int race = 0;
                        mpq_read_value(race, buf, &head);
                        printf("INF / player %d - race is %u\n", i + 1, race);
                        
                        head += 4; // fixed start position.
                        
                        char player_name[256] = {0};
                        mpq_read_string(player_name, buf, &head);
                        printf("INF / player %d - name is %s\n", i + 1, player_name);
                        
                        head += 4; // start position x.
                        head += 4; // start position y.
                        head += 4; // ally low priority.
                        head += 4; // ally high priority.
                    }
                    
                    unsigned int number_teams = 0;
                    mpq_read_value(number_teams, buf, &head);
                    printf("INF / number of teams is %u\n", number_teams);
                    
                    for (unsigned int i = 0; i < number_teams; i++) {
                        unsigned int flags = 0;
                        mpq_read_value(flags, buf, &head);
                        printf("INF / team %d - flags is %u\n", i + 1, flags);
                        
                        unsigned int player_mask = 0;
                        mpq_read_value(player_mask, buf, &head);
                        printf("INF / team %d - player mask is %u\n", i + 1, player_mask);
                        
                        char team_name[256] = {0};
                        mpq_read_string(team_name, buf, &head);
                        printf("INF / team %d - name is %s\n", i + 1, team_name);
                    }
                    
                    SFileCloseFile(mpq);
                }
                
                sha1_final(&conn.map.sha1);
                
                printf(" OK / all files were read successfuly.\n");
                
                to_client.size = 0;
                packet_server_start_adv_ex3(&to_client, &conn.map);
                if (!send_packet(client_fd, &to_client, "start adv ex3 auth check"))
                    goto exit;
            } break;
            
            // SID_STARTADVEX3
            case 0x1c: {
                unsigned int head = 0;
                unsigned int status = 0;
                packet_read_value(status, &from_client, &head);
                printf("status is %u\n", status);
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