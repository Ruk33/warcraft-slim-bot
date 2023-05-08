enum game_state {
    game_public = 16,
    game_private = 17,
    game_closed = 18,
};

enum game_map_type {
    game_map_type_unknown = 1,
    game_map_type_melee = 1 << 5,
    // todo: complete...
};

struct game_name {
    char name[32];
};
