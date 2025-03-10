#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "ft_ssl.h"

/**
 * @brief Read num_bytes from /dev/urandom and store them in buffer.
 *
 * @param buffer The buffer to store the random bytes.
 * @param num_bytes The number of random bytes to read.
 * @return int 0 on success, -1 on failure.
 */
int rand_bytes(u8* buffer, u32 num_bytes)
{
    int urandom = open(URANDOM_PATH, O_RDONLY);
    if (urandom < 0) {
        assert(0);
    }

    ssize_t bytes_read = read(urandom, buffer, num_bytes);

    close(urandom);

    if (bytes_read < 0) {
        assert(0);
    }

    return 0;
}

u64 rand_num(u32 bits)
{
    u64 random;
    rand_bytes((u8*)&random, sizeof(uint64_t));
    random &= (1 << bits) - 1;

    return random;
}

int cmd_rand(u32 num_bytes)
{
    unsigned char* buffer = malloc(sizeof(u8) * num_bytes + 1);
    if (buffer == NULL) {
        assert(0);
    }
    buffer[num_bytes] = '\0';

    rand_bytes(buffer, num_bytes);

    write(STDOUT_FILENO, buffer, num_bytes);

    free(buffer);

    return 0;
}
