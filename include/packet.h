struct packet {
    unsigned char buf[1024];
    int size; // -1 if invalid or couldn't read.
};

// alias to be used with basic types such as int, float, etc.
#define packet_write_ex(dest, src) \
packet_write((dest), (unsigned char *) &(src), sizeof(src))

// alias to be used with fixed array.
#define packet_write_array(dest, src) \
packet_write((dest), (unsigned char *) (src), (sizeof(src)))

// +1 null terminator.
#define packet_write_string(dest, src) \
packet_write((dest), (unsigned char *) (src), (strnlen((src), sizeof(src)) + 1))

// append n bytes from src to the end of dest.
void packet_write(struct packet *dest, unsigned char *src, int n);

// call this function before sending the packet. it will
// make sure that the packet has the correct size in the header.
void packet_write_size(struct packet *dest);
