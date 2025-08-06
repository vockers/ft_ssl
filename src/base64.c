#include "ft_ssl.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "libft.h"

static const char* base64_table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const u8* data, usize input_length)
{
    if (input_length == 0) {
        return ft_calloc(1, sizeof(char)); // Return empty string if input length is 0
    }

    usize output_length = ((input_length - 1) / 3) * 4 + 4;
    char* output        = malloc(sizeof(char) * (output_length + 1));
    if (output == NULL) {
        return NULL;
    }

    for (usize i = 0, j = 0; i < input_length;) {
        u32 octet_a = (u8)data[i++];
        u32 octet_b = i < input_length ? (u8)data[i++] : 0;
        u32 octet_c = i < input_length ? (u8)data[i++] : 0;

        u32 triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }

    // Add padding if input_length is not a multiple of 3
    for (usize i = 0; i < (3 - (input_length % 3)) % 3; i++)
        output[output_length - 1 - i] = '=';

    output[output_length] = '\0';

    return output;
}
