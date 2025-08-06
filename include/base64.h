#pragma once

#include "utils.h"

typedef struct s_base64_opt
{
    bool  decode;      // decode mode
    char* input_file;  // input file for decoding/encoding
    char* output_file; // output file for decoding/encoding
} t_base64_opt;

/**
 * @brief Encode a byte array to base64.
 *
 * @param data The data to encode.
 * @param input_length The length of the data.
 * @return char* The base64 encoded data.
 */
char* base64_encode(const u8* data, usize input_length);