#!/bin/bash
gcc -Wall -Wextra -Werror -Wno-unused-variable -Wno-parentheses main.c packet.c packet_server.c bsha1.c -o build/warcraft-slim-bot -lbncsutil
