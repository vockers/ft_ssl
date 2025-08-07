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

/**
 * @brief Decode a base64 encoded string.
 *
 * @param input The base64 encoded string.
 * @param output_length Pointer to store the length of the decoded data.
 * @return u8* The decoded data.
 */
u8* base64_decode(const char* input, usize* output_length);