#!/bin/bash
gcc -Wall -Wextra -Werror -Wno-unused-variable -Wno-parentheses main.c packet.c packet_server.c crc32.c -o build/warcraft-slim-bot -lbncsutil -lstorm -lz -lbz2 -lstdc++
