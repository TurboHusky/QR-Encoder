#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "qr.h"

#define EVAL_BUFFER_SIZE 32

#define VERSION_OFFSET 1
#define VERSION_MIN 0
#define VERSION_MAX 39
#define VERSION_MODULE_TOTAL 36
#define GF256_LOG_INDEX 0
#define GF256_ANTILOG_INDEX 1

#define ERR_WORDS_PER_BLOCK 0
#define GROUP_1_BLOCK_COUNT 1
#define GROUP_1_BLOCK_SIZE 2
#define GROUP_2_BLOCK_COUNT 3
#define GROUP_2_BLOCK_SIZE 4

#define ALIGNMENT_POSITIONS_MAX 7
#define ALIGNMENT_PATTERN_OFFSET 2
#define ALIGNMENT_PATTERN_WIDTH 5
#define TIMING_ROW 6

#define EVAL_PATTERN_MASK 0x07ffu
#define EVAL_PATTERN_LEFT 0x07a2u
#define EVAL_PATTERN_RIGHT 0x022fu

#define QR_FORMAT_MASK 0x5412u
#define MICRO_QR_FORMAT_MASK 0X4445u
#define BCH_GENERATOR 0x0537u
#define GOLAY_GENERATOR 0x1f25u

#define BLOCK_TYPE_BIT_COUNT 4
#define CHAR_COUNT_LOW_LIMIT 9
#define CHAR_COUNT_UPPER_LIMIT 26

#define BYTE_MASK 0x04U
#define KANJI_MASK 0x08U
#define ALPHANUMERIC_MASK 0x02U
#define NUMERIC_MASK 0x01U

enum char_encoding_t
{
    BYTE_DATA = 2,
    NUM_DATA = 0,
    ALPHANUMERIC_DATA = 1,
    KANJI_DATA = 3
};

enum encoding_mode_t
{
    ENC_NUMERIC = 0x01u,
    ENC_ALPHA_NUMERIC = 0x02u,
    ENC_BYTE = 0x04u, // latin1
    ENC_KANJI = 0x08u,
    ENC_ECI = 0x07u,
    ENC_STRUCTURED_APPEND = 0x03u,
    ENC_FNC1_1 = 0x05u,
    ENC_FNC1_2 = 0x09u,
    ENC_UNSUPPORTED = 0x0fu
};

// order matches char_encoding_t
int header_sizes[7][4] = {
    {3, 0, 0, 0},
    {5, 4, 0, 0},
    {7, 6, 6, 5},
    {9, 8, 8, 7},
    {14, 13, 12, 12},
    {16, 15, 20, 14},
    {18, 17, 20, 16}};

// 4 MicroQR versions, in order M L H Q
const int micro_error_words[4][4] = {
    {0, 2, 0, 0},
    {6, 5, 0, 0},
    {8, 6, 0, 0},
    {10, 8, 0, 14}};

const int micro_module_capacities[4][4] = {
    {0, 20, 0, 0},
    {32, 40, 0, 0},
    {68, 84, 0, 0},
    {112, 128, 0, 80}};

// From Table 9 ISO-IEC-18004 2015
// 40 versions, in order M, L, H, Q
// Block data - {# error codes per block, # blocks in group 1, size of blocks in group 1, # blocks in group 2, size of blocks in group 2}
const int error_blocks[40][4][5] = {
    {{10, 1, 16, 0, 0}, {7, 1, 19, 0, 0}, {17, 1, 9, 0, 0}, {13, 1, 13, 0, 0}},
    {{16, 1, 28, 0, 0}, {10, 1, 34, 0, 0}, {28, 1, 16, 0, 0}, {22, 1, 22, 0, 0}},
    {{26, 1, 44, 0, 0}, {15, 1, 55, 0, 0}, {22, 2, 13, 0, 0}, {18, 2, 17, 0, 0}},
    {{18, 2, 32, 0, 0}, {20, 1, 80, 0, 0}, {16, 4, 9, 0, 0}, {26, 2, 24, 0, 0}},
    {{24, 2, 43, 0, 0}, {26, 1, 108, 0, 0}, {22, 2, 11, 2, 12}, {18, 2, 15, 2, 16}},
    {{16, 4, 27, 0, 0}, {18, 2, 68, 0, 0}, {28, 4, 15, 0, 0}, {24, 4, 19, 0, 0}},
    {{18, 4, 31, 0, 0}, {20, 2, 78, 0, 0}, {26, 4, 13, 1, 14}, {18, 2, 14, 4, 15}},
    {{22, 2, 38, 2, 39}, {24, 2, 97, 0, 0}, {26, 4, 14, 2, 15}, {22, 4, 18, 2, 19}},
    {{22, 3, 36, 2, 37}, {30, 2, 116, 0, 0}, {24, 4, 12, 4, 13}, {20, 4, 16, 4, 17}},
    {{26, 4, 43, 1, 44}, {18, 2, 68, 2, 69}, {28, 6, 15, 2, 16}, {24, 6, 19, 2, 20}},
    {{30, 1, 50, 4, 51}, {20, 4, 81, 0, 0}, {24, 3, 12, 8, 13}, {28, 4, 22, 4, 23}},
    {{22, 6, 36, 2, 37}, {24, 2, 92, 2, 93}, {28, 7, 14, 4, 15}, {26, 4, 20, 6, 21}},
    {{22, 8, 37, 1, 38}, {26, 4, 107, 0, 0}, {22, 12, 11, 4, 12}, {24, 8, 20, 4, 21}},
    {{24, 4, 40, 5, 41}, {30, 3, 115, 1, 116}, {24, 11, 12, 5, 13}, {20, 11, 16, 5, 17}},
    {{24, 5, 41, 5, 42}, {22, 5, 87, 1, 88}, {24, 11, 12, 7, 13}, {30, 5, 24, 7, 25}},
    {{28, 7, 45, 3, 46}, {24, 5, 98, 1, 99}, {30, 3, 15, 13, 16}, {24, 15, 19, 2, 20}},
    {{28, 10, 46, 1, 47}, {28, 1, 107, 5, 108}, {28, 2, 14, 17, 15}, {28, 1, 22, 15, 23}},
    {{26, 9, 43, 4, 44}, {30, 5, 120, 1, 121}, {28, 2, 14, 19, 15}, {28, 17, 22, 1, 23}},
    {{26, 3, 44, 11, 45}, {28, 3, 113, 4, 114}, {26, 9, 13, 16, 14}, {26, 17, 21, 4, 22}},
    {{26, 3, 41, 13, 42}, {28, 3, 107, 5, 108}, {28, 15, 15, 10, 16}, {30, 15, 24, 5, 25}},
    {{26, 17, 42, 0, 0}, {28, 4, 116, 4, 117}, {30, 19, 16, 6, 17}, {28, 17, 22, 6, 23}},
    {{28, 17, 46, 0, 0}, {28, 2, 111, 7, 112}, {24, 34, 13, 0, 0}, {30, 7, 24, 16, 25}},
    {{28, 4, 47, 14, 48}, {30, 4, 121, 5, 122}, {30, 16, 15, 14, 16}, {30, 11, 24, 14, 25}},
    {{28, 6, 45, 14, 46}, {30, 6, 117, 4, 118}, {30, 30, 16, 2, 17}, {30, 11, 24, 16, 25}},
    {{28, 8, 47, 13, 48}, {26, 8, 106, 4, 107}, {30, 22, 15, 13, 16}, {30, 7, 24, 22, 25}},
    {{28, 19, 46, 4, 47}, {28, 10, 114, 2, 115}, {30, 33, 16, 4, 17}, {28, 28, 22, 6, 23}},
    {{28, 22, 45, 3, 46}, {30, 8, 122, 4, 123}, {30, 12, 15, 28, 16}, {30, 8, 23, 26, 24}},
    {{28, 3, 45, 23, 46}, {30, 3, 117, 10, 118}, {30, 11, 15, 31, 16}, {30, 4, 24, 31, 25}},
    {{28, 21, 45, 7, 46}, {30, 7, 116, 7, 117}, {30, 19, 15, 26, 16}, {30, 1, 23, 37, 24}},
    {{28, 19, 47, 10, 48}, {30, 5, 115, 10, 116}, {30, 23, 15, 25, 16}, {30, 15, 24, 25, 25}},
    {{28, 2, 46, 29, 47}, {30, 13, 115, 3, 116}, {30, 23, 15, 28, 16}, {30, 42, 24, 1, 25}},
    {{28, 10, 46, 23, 47}, {30, 17, 115, 0, 0}, {30, 19, 15, 35, 16}, {30, 10, 24, 35, 25}},
    {{28, 14, 46, 21, 47}, {30, 17, 115, 1, 116}, {30, 11, 15, 46, 16}, {30, 29, 24, 19, 25}},
    {{28, 14, 46, 23, 47}, {30, 13, 115, 6, 116}, {30, 59, 16, 1, 17}, {30, 44, 24, 7, 25}},
    {{28, 12, 47, 26, 48}, {30, 12, 121, 7, 122}, {30, 22, 15, 41, 16}, {30, 39, 24, 14, 25}},
    {{28, 6, 47, 34, 48}, {30, 6, 121, 14, 122}, {30, 2, 15, 64, 16}, {30, 46, 24, 10, 25}},
    {{28, 29, 46, 14, 47}, {30, 17, 122, 4, 123}, {30, 24, 15, 46, 16}, {30, 49, 24, 10, 25}},
    {{28, 13, 46, 32, 47}, {30, 4, 122, 18, 123}, {30, 42, 15, 32, 16}, {30, 48, 24, 14, 25}},
    {{28, 40, 47, 7, 48}, {30, 20, 117, 4, 118}, {30, 10, 15, 67, 16}, {30, 43, 24, 22, 25}},
    {{28, 18, 47, 31, 48}, {30, 19, 118, 6, 119}, {30, 20, 15, 61, 16}, {30, 34, 24, 34, 25}}};

struct buffer_t
{
    uint8_t *data;
    size_t size;
    size_t byte_index;
    uint8_t bit_index;
};

void add_to_buffer(uint16_t data, int bitcount, struct buffer_t *const buffer)
{
    data <<= 16 - bitcount;
    while (bitcount > 0)
    {
        int available = 8 - buffer->bit_index;
        int filled = (bitcount > available) ? available : bitcount;
        buffer->data[buffer->byte_index] |= (uint8_t)(data >> (8 + buffer->bit_index));
        data <<= filled;
        bitcount -= filled;
        buffer->bit_index += (uint8_t)filled;
        buffer->byte_index += (buffer->bit_index & 0x08u) >> 3;
        buffer->bit_index &= 0x07u;
    }
}

uint8_t read_bit_stream(struct buffer_t *const buffer)
{
    uint8_t result = (buffer->data[buffer->byte_index] >> buffer->bit_index) & 1;
    --buffer->bit_index;
    buffer->bit_index &= 0x07u;
    buffer->byte_index += (size_t)((buffer->bit_index + 1) >> 3);
    return (uint8_t)(~(result * 0xffu));
}

void qr_free(struct qr_data_t *qr_code)
{
    free(qr_code->data);
    qr_code->data = NULL;
}

void export_test(const char *const name, const int qr_width, const int bit_offset, const uint8_t *const data)
{
    FILE *test = fopen(name, "wb");

    fprintf(test, "P6 %d %d 1\n", qr_width, qr_width);
    for (int r = 0; r < qr_width; r++)
    {
        for (int c = 0; c < qr_width; c++)
        {
            uint8_t buffer[3];
            buffer[0] = buffer[1] = buffer[2] = (data[r * qr_width + c] >> bit_offset) & 0x01u;
            fwrite(&buffer, 3, 1, test);
        }
    }
    fclose(test);
}

// output:  10 bits for 3 digits
//           7 bits for 2
//           4 bits for 1
void encode_numeric(const struct buffer_t input, struct buffer_t *const output)
{
    size_t index = 0;

    while (index < input.size - 2)
    {
        uint8_t a = input.data[index];
        uint8_t b = input.data[index + 1];
        uint8_t c = input.data[index + 2];

        uint16_t encoded = (uint16_t)((a - '0') * 100 + (b - '0') * 10 + (c - '0'));
        add_to_buffer(encoded, 10, output);

        index += 3;
    }

    switch (input.size - index)
    {
    case 2:
        printf("7 residual bits\n");
        add_to_buffer((uint16_t)((input.data[index] - '0') * 10 + input.data[index + 1] - '0'), 7, output);
        break;
    case 1:
        printf("4 residual bits\n");
        add_to_buffer(input.data[index] - '0', 4, output);
        break;
    default:
        break;
    }
}

// output:  11 bits per pair
//           6 bits for a single character
void encode_alphanumeric(const struct buffer_t input, struct buffer_t *const output)
{
    const char alphanumeric_lookup[256] = {
        36, 0, 0, 0, 37, 38, 0, 0, 0, 0, 39, 40, 0, 41, 42, 43,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 44, 0, 0, 0, 0, 0,
        0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35};
    size_t index = 0;

    while (index < input.size - 1)
    {
        uint8_t hi_byte = input.data[index] - 32;
        uint8_t lo_byte = input.data[index + 1] - 32;
        uint16_t code = (uint16_t)(45 * alphanumeric_lookup[hi_byte] + alphanumeric_lookup[lo_byte]);
        add_to_buffer(code, 11, output);
        index += 2;
    }
    
    if (index < input.size)
    {
        uint8_t byte = input.data[index] - 32;
        uint16_t code = (uint16_t)alphanumeric_lookup[byte];
        add_to_buffer(code, 6, output);
    }
}

void encode_kanji(const struct buffer_t input, struct buffer_t *const output)
{
    for (size_t i = 0; i < input.size; i += 2)
    {
        uint16_t temp = (input.data[i] << 8) | input.data[i];
        if (temp < 0x9FFC)
        {
            temp -= 0x8140;
        }
        else
        {
            temp -= 0xC140;
        }
        uint16_t low = temp & 0x00FF;
        temp >>= 8;
        temp *= 0xC0;
        temp += low;
        add_to_buffer(temp, 13, output);
    }
}

void encode_byte(const struct buffer_t input, struct buffer_t *const output)
{
    for (size_t i = 0; i < input.size; ++i)
    {
        add_to_buffer(input.data[i], 8, output);
    }
}

static inline enum char_encoding_t input_type(const char byte1, const char byte2)
{
    if (byte1 >= '0' && byte1 <= '9')
    {
        return NUM_DATA;
    }
    if ((byte1 >= 'A' && byte1 <= 'Z') || ' ' == byte1 || '$' == byte1 || '%' == byte1 || '*' == byte1 || '+' == byte1 || '-' == byte1 || '.' == byte1 || '/' == byte1 || ':' == byte1)
    {
        return ALPHANUMERIC_DATA;
    }
    if ((byte1 >= '\x81' && byte1 <= '\x9F') || (byte1 >= '\xE0' && byte1 <= '\xEF'))
    {
        if (byte2 >= '\x40' && byte2 <= '\xFC' && byte2 != '\x7F')
        {
            return KANJI_DATA;
        }
    }
    // katakana in range 0xA1u to 0xDFu, fall back to byte
    return BYTE_DATA;
}

size_t encoding_size(const enum char_encoding_t type, const size_t char_count)
{
    switch (type)
    {
    case NUM_DATA:
    {
        size_t remainder_bits[] = {0, 4, 7};
        return (char_count / 3) * 10 + remainder_bits[char_count % 3];
    }
    case BYTE_DATA:
        return char_count << 3;
    case KANJI_DATA:
        return (char_count >> 1) * 13;
    case ALPHANUMERIC_DATA:
        return (char_count >> 1) * 11 + ((char_count & 0x01U) ? 6 : 0);
    }
    return 0; // Should never happen
}

enum merge_t
{
    UNABLE_TO_MERGE,
    DO_NOT_MERGE,
    MERGE_WITH_LAST,
    MERGE_WITH_NEXT
};

enum merge_t analyse_data(const int header_index, const enum char_encoding_t last_type, const enum char_encoding_t next_type, const enum char_encoding_t data_type, const size_t char_count, const enum char_encoding_t check_type)
{
    size_t cost = encoding_size(data_type, char_count) + (size_t)header_sizes[header_index][data_type];
    size_t base_cost = encoding_size(check_type, char_count);

    // printf("%s cost: %lu ", BYTE_DATA == data_type ? "Byte" : KANJI_DATA == data_type ? "Kanji" : ALPHANUMERIC_DATA == data_type ? "Alpha" : "Num", cost);
    if (check_type == last_type)
    {
        if (last_type == next_type)
        {
            cost += (size_t)header_sizes[header_index][check_type];
            // printf("(+HDR %lu) ", header_sizes[header_index][check_type]);
        }
        // printf("/ %lu collapse with previous %s data? %s\n", base_cost, BYTE_DATA == check_type ? "Byte" : KANJI_DATA == check_type      ? "Kanji" : ALPHANUMERIC_DATA == check_type ? "Alpha" : "Num", cost > base_cost ? "yes" : "no");
        return (cost > base_cost) ? MERGE_WITH_LAST : DO_NOT_MERGE;
    }
    else if (check_type == next_type)
    {
        // printf("/ %lu collapse with following %s data? %s\n", base_cost, BYTE_DATA == check_type ? "Byte" : KANJI_DATA == check_type      ? "Kanji" : ALPHANUMERIC_DATA == check_type ? "Alpha" : "Num", cost > base_cost ? "yes" : "no");
        return (cost > base_cost) ? MERGE_WITH_NEXT : DO_NOT_MERGE;
    }
    // printf("unable to merge\n");
    return UNABLE_TO_MERGE;
}

enum merge_t analyse_numeric_data(const int header_index, const enum char_encoding_t last, const enum char_encoding_t next, const enum char_encoding_t type, const size_t char_count)
{
    if (NUM_DATA == type)
    {
        return analyse_data(header_index, last, next, type, char_count, ALPHANUMERIC_DATA);
    }
    return UNABLE_TO_MERGE;
}

enum merge_t analyse_alpha_kanji_data(const int header_index, const enum char_encoding_t last, const enum char_encoding_t next, const enum char_encoding_t type, const size_t char_count)
{
    if (BYTE_DATA != type)
    {
        return analyse_data(header_index, last, next, type, char_count, BYTE_DATA);
    }
    return UNABLE_TO_MERGE;
}

typedef enum merge_t (*comparator_t)(const int header_index, const enum char_encoding_t last, const enum char_encoding_t next, const enum char_encoding_t type, const size_t char_count);

struct encoding_run_t
{
    enum char_encoding_t type;
    size_t char_count;
};

void merge_data(const int header_index, struct encoding_run_t *const list, const size_t list_size, const comparator_t eval_callback)
{
    size_t index = 1;
    while (index < list_size)
    {
        if (list[index].type == list[index - 1].type)
        {
            list[index].char_count += list[index - 1].char_count;
            list[index - 1].char_count = 0;
            ++index;
            continue;
        }
        enum merge_t merge = eval_callback(header_index, list[index - 1].type, list[index + 1].type, list[index].type, list[index].char_count);
        if (MERGE_WITH_LAST == merge)
        {
            list[index].type = list[index - 1].type;
            list[index].char_count += list[index - 1].char_count;
            list[index - 1].char_count = 0;
        }
        if (MERGE_WITH_NEXT == merge)
        {
            list[index + 1].char_count += list[index].char_count;
            list[index].char_count = 0;
            ++index;
        }
        ++index;
    }
}

void calculate_error_codes(const int data_word_count, const int error_word_count, const uint8_t (*const gf256_lookup)[2], const int generator_start, const int generator_end, const uint8_t *const generator, const uint8_t *const input, uint8_t *error_words)
{
    if (data_word_count < error_word_count)
    {
        memcpy(error_words, input, (size_t)data_word_count);
        memset(error_words + data_word_count, 0, (size_t)(error_word_count - data_word_count));
    }
    else
    {
        memcpy(error_words, input, (size_t)error_word_count);
    }

    for (int j = 0; j < data_word_count; ++j)
    {
        if (0 == error_words[0])
        {
            for (size_t k = 1; k < (size_t)error_word_count; ++k)
            {
                error_words[k - 1] = error_words[k];
            }
            if (j + error_word_count < data_word_count)
            {
                error_words[error_word_count - 1] = input[j + error_word_count];
            }
            else
            {
                error_words[error_word_count - 1] = 0;
            }
            continue;
        }

        uint8_t temp;
        uint8_t gen_mult = gf256_lookup[error_words[0]][GF256_ANTILOG_INDEX]; // Generator multiplication factor
        for (size_t k = 1; k < (size_t)error_word_count; ++k)
        {
            // Multiply generator by leading term in data polynomial (add antilogs mod 255)
            temp = (uint8_t)((gen_mult + gf256_lookup[generator[(unsigned int)generator_start + k]][GF256_ANTILOG_INDEX]) % 255);
            // Add generator to data polynomial (XOR to cancel leading term)
            error_words[k - 1] = gf256_lookup[temp][GF256_LOG_INDEX] ^ error_words[k];
        }
        temp = (uint8_t)((gen_mult + gf256_lookup[generator[generator_end]][GF256_ANTILOG_INDEX]) % 255);
        if (j + error_word_count < data_word_count)
        {
            error_words[error_word_count - 1] = gf256_lookup[temp][GF256_LOG_INDEX] ^ input[j + error_word_count];
        }
        else
        {
            error_words[error_word_count - 1] = gf256_lookup[temp][GF256_LOG_INDEX];
        }
    }
    for (int k = 0; k < error_word_count; ++k)
    {
        printf("%02x ", error_words[k]);
    }
    printf("\n");
}

// See Table 1 of ISO-IEC-18004
int compute_alignment_positions(const int version, int *const coords) // version 1-40
{
    if (version <= VERSION_MIN + VERSION_OFFSET)
    {
        return 0;
    }
    int intervals = (version / 7) + 1;                              // Number of gaps between alignment patterns
    int distance = 4 * version + 4;                                 // Distance between first and last alignment pattern
    int step = (int)(lround((double)distance / (double)intervals)); // Round equal spacing to nearest integer
    step += step & 1;                                               // Round step to next even number
    coords[0] = 6;                                                  // First coordinate is always 6 (can't be calculated with step)
    for (int i = 1; i <= intervals; ++i)
    {
        coords[i] = 6 + distance - step * (intervals - i); // Start right/bottom and go left/up by step*k
    }
    return intervals + 1;
}

int qr_size(const int version, const int alignment_pattern_count) // version 1-40
{
    int N = 17 + version * 4;             // QR width
    int free_modules = N * (N - 2) - 191; // ((N - 17) x 8) x 2 + (N - 9)^2
    if (version > 1)
    {
        free_modules -= alignment_pattern_count * (alignment_pattern_count * 25 - 10) - 55; // (M - 2) x 20 x 2 + (M - 1)^2 x 25
    }
    if (version > 6)
    {
        free_modules -= VERSION_MODULE_TOTAL;
    }
    return free_modules;
}

struct fill_settings_t
{
    int qr_width;
    struct
    {
        const int *positions;
        int size;
    } alignment;
    uint8_t masks[12][12];
};

void fill_u(struct buffer_t *const input, const int col, const int row_start, const int row_end, const int align_start, const int align_end, const struct fill_settings_t *const settings, uint8_t *const output)
{
    (void)input;

    int align_x = settings->alignment.size - 1;
    while (align_x >= 0 && col < settings->alignment.positions[align_x] - ALIGNMENT_PATTERN_OFFSET)
    {
        --align_x;
    }

    int index = row_end;
    if (align_x < 0 || col > settings->alignment.positions[align_x] + ALIGNMENT_PATTERN_OFFSET)
    {
        while (index >= row_start)
        {
            output[settings->qr_width * index + col] = read_bit_stream(input) ^ settings->masks[index % 12][col % 12];
            output[settings->qr_width * index + col - 1] = read_bit_stream(input) ^ settings->masks[index % 12][(col - 1) % 12];
            --index;
        }
        return;
    }

    int align_y = align_end;
    while (index >= row_start)
    {
        while (align_y >= align_start && index < settings->alignment.positions[align_y] - ALIGNMENT_PATTERN_OFFSET)
        {
            --align_y;
        }

        int limit = row_start - 1;
        if (align_y >= align_start) // Have at least one alignment pattern to check
        {
            limit = settings->alignment.positions[align_y] + ALIGNMENT_PATTERN_OFFSET;
            if (index <= limit) // Inside alignment pattern
            {
                limit = settings->alignment.positions[align_y] - ALIGNMENT_PATTERN_OFFSET - 1;
                if (limit < row_start) // Check for timing pattern
                {
                    limit = row_start - 1;
                }
                if (col == settings->alignment.positions[align_x] - ALIGNMENT_PATTERN_OFFSET)
                {
                    while (index > limit)
                    {
                        output[settings->qr_width * index + col - 1] = read_bit_stream(input) ^ settings->masks[index % 12][(col - 1) % 12];
                        --index;
                    }
                }
                else
                {
                    index = limit;
                }
            }
        }
        while (index > limit)
        {
            output[settings->qr_width * index + col] = read_bit_stream(input) ^ settings->masks[index % 12][col % 12];
            output[settings->qr_width * index + col - 1] = read_bit_stream(input) ^ settings->masks[index % 12][(col - 1) % 12];
            --index;
        }
    }
}

void fill_d(struct buffer_t *const input, const int col, const int row_start, const int row_end, const int align_start, const int align_end, const struct fill_settings_t *const settings, uint8_t *const output)
{
    (void)input;

    int align_x = settings->alignment.size - 1;
    while (align_x >= 0 && col < settings->alignment.positions[align_x] - ALIGNMENT_PATTERN_OFFSET)
    {
        --align_x;
    }

    int index = row_start;
    if (align_x < 0 || col > settings->alignment.positions[align_x] + ALIGNMENT_PATTERN_OFFSET)
    {
        while (index <= row_end)
        {
            output[settings->qr_width * index + col] = read_bit_stream(input) ^ settings->masks[index % 12][col % 12];
            output[settings->qr_width * index + col - 1] = read_bit_stream(input) ^ settings->masks[index % 12][(col - 1) % 12];
            ++index;
        }
        return;
    }

    int align_y = align_start;
    while (index <= row_end)
    {
        while (align_y <= align_end && index > settings->alignment.positions[align_y] + ALIGNMENT_PATTERN_OFFSET)
        {
            ++align_y;
        }

        int limit = row_end + 1;
        if (align_y <= align_end) // Have at least one alignment pattern to check
        {
            limit = settings->alignment.positions[align_y] - ALIGNMENT_PATTERN_OFFSET;
            if (index >= limit) // Inside alignment pattern
            {
                limit = settings->alignment.positions[align_y] + ALIGNMENT_PATTERN_OFFSET + 1;
                if (limit > row_end) // Check for timing pattern
                {
                    limit = row_end + 1;
                }
                if (col == settings->alignment.positions[align_x] - ALIGNMENT_PATTERN_OFFSET)
                {
                    while (index < limit)
                    {
                        output[settings->qr_width * index + col - 1] = read_bit_stream(input) ^ settings->masks[index % 12][(col - 1) % 12];
                        ++index;
                    }
                }
                else
                {
                    index = limit;
                }
            }
        }
        while (index < limit)
        {
            output[settings->qr_width * index + col] = read_bit_stream(input) ^ settings->masks[index % 12][col % 12];
            output[settings->qr_width * index + col - 1] = read_bit_stream(input) ^ settings->masks[index % 12][(col - 1) % 12];
            ++index;
        }
    }
}

int pattern_score(const int module, uint16_t *const buffer)
{
    *buffer <<= 1;
    *buffer |= (uint16_t)module;
    *buffer &= EVAL_PATTERN_MASK;
    if ((EVAL_PATTERN_LEFT == *buffer) || (EVAL_PATTERN_RIGHT == *buffer))
    {
        return 40;
    }
    return 0;
}

int repeat_score(const int module, int *const last_module, int *const run)
{
    int score = 0;
    if (module == *last_module)
    {
        ++*run;
    }
    else
    {
        if (*run >= 5)
        {
            score = *run - 2;
        }
        *last_module = module;
        *run = 1;
    }
    return score;
}

int calculate_capacity(const int version, const int correction_level, const enum encoding_mode_t mode)
{
    const int *block_data = error_blocks[version][correction_level];
    int data_bits = (block_data[1] * block_data[2] + block_data[3] * block_data[4]) << 3;

    data_bits -= BLOCK_TYPE_BIT_COUNT;
    int char_count;
    int length_bits;
    int remainder;
    switch (mode)
    {
    case ENC_NUMERIC:
        length_bits = (version < CHAR_COUNT_LOW_LIMIT) ? 10 : (version < CHAR_COUNT_UPPER_LIMIT) ? 12
                                                                                                 : 14;
        data_bits -= length_bits;
        char_count = (data_bits / 10) * 3;
        remainder = data_bits % 10;
        if (remainder >= 7)
        {
            char_count += 2;
        }
        else if (remainder >= 4)
        {
            ++char_count;
        }
        break;
    case ENC_ALPHA_NUMERIC:
        length_bits = (version < CHAR_COUNT_LOW_LIMIT) ? 9 : (version < CHAR_COUNT_UPPER_LIMIT) ? 11
                                                                                                : 13;
        data_bits -= length_bits;
        remainder = data_bits % 11;
        char_count = (data_bits / 11) * 2;
        char_count += (remainder >= 6) ? 1 : 0;
        break;
    case ENC_BYTE:
        length_bits = (version < CHAR_COUNT_LOW_LIMIT) ? 8 : 16;
        data_bits -= length_bits;
        char_count = data_bits >> 3;
        break;
    case ENC_KANJI:
        length_bits = (version < CHAR_COUNT_LOW_LIMIT) ? 8 : (version < CHAR_COUNT_UPPER_LIMIT) ? 10
                                                                                                : 12;
        data_bits -= length_bits;
        char_count = data_bits / 13;
        break;
    default:
        // Unrecognised format
        printf("ERROR: Unrecognised format\n");
        return 0;
    }

    return char_count;
}

struct qr_data_t *qr_encode(const int qr_version, const enum error_correction_level_t correction_level, enum code_type_t code_type, const char *const buffer)
{
    (void) qr_version;
    (void) code_type;
    // const uint8_t ncodes[7][4] = {{3,0,0,0},{4,3,0,0},{5,4,4,3},{6,5,5,4},{10,9,8,8},{12,11,16,10},{14,13,16,12}};
    // const char *const data2 = "\x9A\x9F\x40\xC6\xE5\xB7\xC8\x5C\x9F\x69";


    // Worst case encoding size is byte mode version 27+:
    // 8 bits per char, 4 bit mode, 16 bit length, 4 bit terminator

    if (buffer[0] == '\0')
    {
        return NULL;
    }

    // ================================================================
    // Check input types
    // ================================================================

    size_t list_capacity = EVAL_BUFFER_SIZE;
    struct encoding_run_t *encoding_list = (struct encoding_run_t *)malloc(list_capacity * sizeof(struct encoding_run_t));
    size_t list_size = 0;

    enum char_encoding_t type = BYTE_DATA;
    size_t run = 0;
    size_t char_count = 0;
    uint8_t data_masks[] = {NUMERIC_MASK, ALPHANUMERIC_MASK, BYTE_MASK, KANJI_MASK};
    uint8_t data_types = 0;
    while (buffer[char_count] != '\0')
    {
        enum char_encoding_t new_type = input_type(buffer[char_count], buffer[char_count + 1]);
        data_types |= data_masks[new_type];
        if (new_type == type)
        {
            ++run;
        }
        else
        {
            if (list_size >= list_capacity - 1)
            {
                list_capacity <<= 1;
                encoding_list = (struct encoding_run_t *)realloc(encoding_list, list_capacity * sizeof(struct encoding_run_t));
                if (NULL == encoding_list)
                {
                    printf("Failed to increase buffer list size\n");
                    return NULL;
                }
            }
            encoding_list[list_size].type = type;
            encoding_list[list_size].char_count = run;
            ++list_size;

            type = new_type;
            run = 1;
        }
        if (KANJI_DATA == type)
        {
            ++char_count;
            if (buffer[char_count] == '\0')
            {
                break;
            }
        }
        ++char_count;
    }
    encoding_list[list_size].type = type;
    encoding_list[list_size].char_count = run;
    ++list_size;

    struct encoding_run_t *final_list = (struct encoding_run_t *)malloc((list_size + 1) * sizeof(struct encoding_run_t));
    printf("Input: %lu bytes\n", char_count);

    // M1, M2, M3, M4, 1-9, 10-26, 27-40
    int module_limits[7] = {
        micro_module_capacities[0][correction_level],
        micro_module_capacities[1][correction_level],
        micro_module_capacities[2][correction_level],
        micro_module_capacities[3][correction_level],
        (error_blocks[8][correction_level][1] * error_blocks[8][correction_level][2] + error_blocks[8][correction_level][3] * error_blocks[8][correction_level][4]) << 3,
        (error_blocks[25][correction_level][1] * error_blocks[25][correction_level][2] + error_blocks[25][correction_level][3] * error_blocks[25][correction_level][4]) << 3,
        (error_blocks[39][correction_level][1] * error_blocks[39][correction_level][2] + error_blocks[39][correction_level][3] * error_blocks[39][correction_level][4]) << 3};
    int header_index = 4;
    if (CORRECTION_LEVEL_H != correction_level)
    {
        header_index = 3;
    }
    if ((CORRECTION_LEVEL_L == correction_level) || (CORRECTION_LEVEL_M == correction_level))
    {
        if (0 == (data_types & ~(NUMERIC_MASK | ALPHANUMERIC_MASK)))
        {
            header_index = 1;
        }
        else
        {
            header_index = 2;
        }
    }
    if (0 == (data_types & ~NUMERIC_MASK)) // No EC, only detection
    {
        header_index = 0;
    }
    printf("Starting index: %d\n", header_index);

    int module_count = 0;
    while (header_index < 7)
    {
        if (module_count < module_limits[header_index])
        {
            memcpy(final_list, encoding_list, list_size * sizeof(struct encoding_run_t));
            final_list[list_size].type = type;
            final_list[list_size].char_count = 0;

            merge_data(header_index, final_list, list_size, analyse_numeric_data);
            merge_data(header_index, final_list, list_size, analyse_alpha_kanji_data);

            module_count = 0;
            for (int j = 0; j < (int)list_size; ++j)
            {
                if (final_list[j].char_count > 0)
                {
                    module_count += header_sizes[header_index][final_list[j].type];
                    module_count += (int)encoding_size(final_list[j].type, final_list[j].char_count);
                    printf("%s%lu, ", (BYTE_DATA == final_list[j].type) ? "B" : (KANJI_DATA == final_list[j].type)      ? "K"
                                                                            : (ALPHANUMERIC_DATA == final_list[j].type) ? "A"
                                                                                                                        : "N",
                           final_list[j].char_count);
                }
            }
            printf("data module total: %d, limit: %d\n", module_count, module_limits[header_index]);

            if (module_count <= module_limits[header_index])
            {
                break;
            }
        }
        ++header_index;
    }

    if (header_index > 6)
    {
        printf("Error\n");
        return NULL;
    }

    enum code_type_t qr_type = QR_SIZE_STANDARD;
    int version = 39;
    size_t data_word_total = 0;
    size_t error_word_total = 0;
    if (header_index < 4)
    {
        qr_type = QR_SIZE_MICRO;
        version = header_index;
        data_word_total = (size_t)(((micro_module_capacities[version][correction_level] + 4) >> 3));
        error_word_total = (size_t)micro_error_words[version][correction_level];
    }
    else
    {
        const int *block_data;
        int max_versions[] = {8, 25, 39};
        version = max_versions[header_index - 4];
        while (version > 0)
        {
            block_data = error_blocks[version - 1][correction_level];
            int capacity = (block_data[GROUP_1_BLOCK_COUNT] * block_data[GROUP_1_BLOCK_SIZE] + block_data[GROUP_2_BLOCK_COUNT] * block_data[GROUP_2_BLOCK_SIZE]) << 3;
            if (module_count > capacity)
            {
                break;
            }
            --version;
        }
        block_data = error_blocks[version][correction_level];
        data_word_total = (size_t)(block_data[GROUP_1_BLOCK_COUNT] * block_data[GROUP_1_BLOCK_SIZE] + block_data[GROUP_2_BLOCK_COUNT] * block_data[GROUP_2_BLOCK_SIZE]);
        error_word_total = (size_t)(block_data[ERR_WORDS_PER_BLOCK] * (block_data[GROUP_1_BLOCK_COUNT] + block_data[GROUP_2_BLOCK_COUNT]));
    }

    char correction_map[] = {'M', 'L', 'H', 'Q'};
    printf("Version: %d, %s %c, %lu+%lu data+error words\n", version + VERSION_OFFSET, QR_SIZE_STANDARD == qr_type ? "QR" : "MicroQR", correction_map[correction_level], data_word_total, error_word_total);
    typedef void (*encoder_t)(const struct buffer_t, struct buffer_t *const);
    encoder_t encoders[4] = {encode_numeric, encode_alphanumeric, encode_byte, encode_kanji};
    struct buffer_t encoder_buffer = {.bit_index = 0, .byte_index = 0, .size = data_word_total + error_word_total};
    size_t offset = 0;
    encoder_buffer.data = calloc(encoder_buffer.size, sizeof(uint8_t));
    for (size_t i = 0; i < list_size; ++i)
    {
        if (final_list[i].char_count > 0)
        {
            if (QR_SIZE_MICRO == qr_type)
            {
                uint16_t count_indicator_lengths[4][4] = {{3, 0, 0, 0}, {4, 3, 0, 0}, {5, 4, 4, 3}, {6, 5, 5, 4}};
                add_to_buffer(final_list[i].type, version, &encoder_buffer);
                add_to_buffer((uint16_t)final_list[i].char_count, count_indicator_lengths[version][final_list[i].type], &encoder_buffer);
            }
            else
            {
                int count_indicator_lengths[4] = {10, 9, 8, 8};
                int bits = count_indicator_lengths[final_list[i].type];
                if (version >= 9)
                {
                    bits += 2;
                }
                if (version >= 26)
                {
                    bits += 2;
                }
                if ((BYTE_DATA == final_list[i].type) && (bits > 8))
                {
                    bits = 16;
                }
                printf("Type: %d Count bits: %d\n", final_list[i].type, bits);
                add_to_buffer(1 << final_list[i].type, 4, &encoder_buffer);
                add_to_buffer((uint16_t)final_list[i].char_count, bits, &encoder_buffer);
            }

            struct buffer_t temp = {.bit_index = 0, .byte_index = 0, .size = final_list[i].char_count};
            temp.data = (uint8_t *)(buffer + offset);
            encoders[final_list[i].type](temp, &encoder_buffer);
            offset += final_list[i].char_count;
        }
    }

    int qr_capacity;

    if (QR_SIZE_MICRO == qr_type)
    {
        qr_capacity = micro_module_capacities[version][correction_level];
    }
    else
    {
        qr_capacity = (error_blocks[version][correction_level][1] * error_blocks[version][correction_level][2] + error_blocks[version][correction_level][3] * error_blocks[version][correction_level][4]) << 3;
    }
    printf("Encoded len check: %d %lu, QR capacity: %d, %d bits unused\n", module_count, (encoder_buffer.byte_index << 3) + (size_t)encoder_buffer.bit_index, qr_capacity, qr_capacity - module_count);

    // Terminators
    int terminator_length = (QR_SIZE_MICRO == qr_type) ? ((version + 1) << 1) + 1 : 4;
    if ((qr_capacity - module_count) > terminator_length)
    {
        add_to_buffer(0, terminator_length, &encoder_buffer);
    }
    // Padding
    encoder_buffer.byte_index += (size_t)((encoder_buffer.bit_index + 0x07) >> 3);
    encoder_buffer.bit_index = 0;
    uint8_t pad_byte = 0xEC;
    while (encoder_buffer.byte_index < (size_t)(qr_capacity >> 3))
    {
        encoder_buffer.data[encoder_buffer.byte_index] = pad_byte;
        ++encoder_buffer.byte_index;
        pad_byte ^= 0xFD;
    }

    printf("Encoded data: ");
    for (size_t i = 0; i < data_word_total; ++i)
    {
        printf("%02x ", encoder_buffer.data[i]);
    }
    printf("\n");

    // ================================================================
    // Error correction
    // ================================================================

    // Generate lookup tables
    uint8_t gf256_lookup[256][2];
    uint16_t gf256_base = 1;
    gf256_lookup[0][1] = 0; // No exponent exists for zero value coefficient
    for (int i = 0; i < 256; ++i)
    {
        gf256_lookup[i][0] = (uint8_t)gf256_base;
        gf256_lookup[gf256_base][1] = (uint8_t)i;
        gf256_base <<= 1;
        if (gf256_base > 255)
        {
            gf256_base ^= 285;
        }
    }
    gf256_lookup[1][1] = 0;
    // for (int i = 0; i< 256; ++i) {printf(" %u %u\n", gf256_lookup[i][0], gf256_lookup[i][1]);}printf("\n");

    // Generate generator polynomial
    int generator_exponent = 2;
    uint8_t generator[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 2};
    int generator_end = sizeof(generator) - 1;
    int new_generator_exponent;

    if (QR_SIZE_MICRO == qr_type)
    {
        new_generator_exponent = micro_error_words[version][correction_level];
    }
    else
    {
        new_generator_exponent = error_blocks[version][correction_level][ERR_WORDS_PER_BLOCK];
    }

    while (generator_exponent < new_generator_exponent)
    {
        ++generator_exponent;
        uint8_t last_generator_value = 0;
        for (int i = 0; i < generator_exponent; ++i)
        {
            uint8_t temp = (gf256_lookup[(gf256_lookup[generator[generator_end - i]][GF256_ANTILOG_INDEX] + generator_exponent - 1) % 255][GF256_LOG_INDEX]) ^ last_generator_value;
            last_generator_value = generator[generator_end - i];
            generator[generator_end - i] = temp;
        }
        generator[generator_end - generator_exponent] = 1;
    }

    printf("Generator exponent: %d (%d terms)\n", generator_exponent, generator_exponent + 1);
    // int generator_size = generator_exponent + 1;
    int generator_start = (int)(sizeof(generator) - (size_t)generator_exponent - 1);
    for (int i = 0; i <= generator_exponent; ++i)
    {
        printf("%d ", generator[generator_end - generator_exponent + i]);
    }
    printf("\n");

    // TEST
    // Input 1-M "HELLO WORLD" (As 1-Q but 6 pad bytes)
    // Order 10 generator:
    // 0 251 67  46  61  118 70 64 94  32  45  (coefficient exponents)
    // 1 216 194 159 111 199 94 95 113 157 193 (antilogs)
    // Result:
    // 196  35  39  119  235  215  231  226  93  23 (error coefficients)
    //
    // Input 5-Q "There\'s a frood who really knows where his towel is!"
    // Order 18 generator:
    // 1 239 251 183 113 149 175 199 215 240 220 73 82 173 75 32 67 217 146 (antilogs)
    // Result:
    // 213 199 11 45 115 247 241 223 229 248 154 117 154 111 86 161 111 39
    // 87 204 96 60 202 182 124 157 200 134 27 129 209 17 163 163 120 133
    // 148 116 177 212 76 133 75 242 238 76 195 230 189 10 108 240 192 141
    // 235 159 5 173 24 147 59 33 106 40 255 172 82 2 131 32 178 236

    printf("Error codes:\n");
    const int (*block_data)[5] = &error_blocks[version][correction_level];

    if (QR_SIZE_MICRO == qr_type)
    {
        printf("Micro QR ");
        calculate_error_codes((int)data_word_total, (int)error_word_total, (const uint8_t (*const)[2])gf256_lookup, generator_start, generator_end, generator, encoder_buffer.data, encoder_buffer.data + data_word_total);
    }
    else
    {
        size_t block_offset = 0;
        size_t err_offset = 0;
        for (int i = 0; i < (*block_data)[GROUP_1_BLOCK_COUNT]; ++i)
        {
            printf("Group 1, Block %d ", i + 1);
            calculate_error_codes((*block_data)[GROUP_1_BLOCK_SIZE], (*block_data)[ERR_WORDS_PER_BLOCK], (const uint8_t (*const)[2])gf256_lookup, generator_start, generator_end, generator, encoder_buffer.data + block_offset, encoder_buffer.data + data_word_total + err_offset);
            block_offset += (size_t)(*block_data)[GROUP_1_BLOCK_SIZE];
            err_offset += (size_t)(*block_data)[ERR_WORDS_PER_BLOCK];
        }
        for (int i = 0; i < (*block_data)[GROUP_2_BLOCK_COUNT]; ++i)
        {
            printf("Group 2, Block %d ", i + 1);
            calculate_error_codes((*block_data)[GROUP_2_BLOCK_SIZE], (*block_data)[ERR_WORDS_PER_BLOCK], (const uint8_t (*const)[2])gf256_lookup, generator_start, generator_end, generator, encoder_buffer.data + block_offset, encoder_buffer.data + data_word_total + err_offset);
            block_offset += (size_t)(*block_data)[GROUP_2_BLOCK_SIZE];
            err_offset += (size_t)(*block_data)[ERR_WORDS_PER_BLOCK];
        }
    }

    // ================================================================
    // Interleave
    // ================================================================

    int alignment_positions[ALIGNMENT_POSITIONS_MAX];
    const int n = compute_alignment_positions(version + VERSION_OFFSET, alignment_positions);
    printf("Free modules: %d (%d bytes)\n", qr_size(version + 1, n), (qr_size(version + 1, n) + 7) >> 3);
    size_t qr_data_size = ((size_t)qr_size(version + 1, n) + 0x07u) >> 3;
    uint8_t *interleaved_data = calloc(qr_data_size, sizeof(uint8_t));
    if (QR_SIZE_MICRO == qr_type)
    {
        memcpy(interleaved_data, encoder_buffer.data, data_word_total + error_word_total);
        if ((0 == version) || (2 == version))
        {
            for (size_t i = 0; i < error_word_total; ++i)
            {
                interleaved_data[data_word_total - 1 + i] |= interleaved_data[data_word_total + i] >> 4;
                interleaved_data[data_word_total + i] <<= 4;
            }
        }
        printf("Data: ");
    }
    else
    {
        // Interleave data words
        int line_index = 0;
        size_t interleaved_index = 0;
        while (line_index < (*block_data)[GROUP_1_BLOCK_SIZE] || line_index < (*block_data)[GROUP_2_BLOCK_SIZE])
        {
            if (line_index < (*block_data)[GROUP_1_BLOCK_SIZE])
            {
                for (int i = 0; i < (*block_data)[GROUP_1_BLOCK_COUNT]; ++i)
                {
                    interleaved_data[interleaved_index] = encoder_buffer.data[i * (*block_data)[GROUP_1_BLOCK_SIZE] + line_index];
                    ++interleaved_index;
                }
            }
            if (line_index < (*block_data)[GROUP_2_BLOCK_SIZE])
            {
                for (int i = 0; i < (*block_data)[GROUP_2_BLOCK_COUNT]; ++i)
                {
                    interleaved_data[interleaved_index] = encoder_buffer.data[((*block_data)[GROUP_1_BLOCK_COUNT] * (*block_data)[GROUP_1_BLOCK_SIZE]) + i * (*block_data)[GROUP_2_BLOCK_SIZE] + line_index];
                    ++interleaved_index;
                }
            }
            ++line_index;
        }

        // Interleave error words
        int num_error_code_blocks = (*block_data)[GROUP_1_BLOCK_COUNT] + (*block_data)[GROUP_2_BLOCK_COUNT];
        for (size_t i = 0; i < (size_t)(*block_data)[ERR_WORDS_PER_BLOCK]; ++i)
        {
            for (size_t j = 0; j < (size_t)num_error_code_blocks; ++j)
            {
                interleaved_data[interleaved_index] = encoder_buffer.data[data_word_total + i + j * (size_t)(*block_data)[ERR_WORDS_PER_BLOCK]];
                ++interleaved_index;
            }
        }
        printf("Interleaved data: ");
    }

    for (size_t i = 0; i < data_word_total + error_word_total; ++i)
    {
        printf("%02x ", interleaved_data[i]);
    }
    printf("\n");

    size_t qr_width = (size_t)(21 + (version << 2));
    if (QR_SIZE_MICRO == qr_type)
    {
        qr_width = (size_t)(11 + (version << 1));
    }
    struct buffer_t qr_buffer = {.bit_index = 0, .byte_index = 0, .size = qr_width * qr_width};
    qr_buffer.data = (uint8_t *)calloc(qr_buffer.size, sizeof(uint8_t));

    // ================================================================
    // Patterns
    // ================================================================

    // Alignment Patterns
    if (QR_SIZE_STANDARD == qr_type)
    {
        const uint8_t alignment_pattern[5] = {0xe0u, 0xeeu, 0xeau, 0xeeu, 0xe0u};
        for (int grid_x = 0; grid_x < n; ++grid_x)
        {
            for (int grid_y = 0; grid_y < n; ++grid_y)
            {
                if ((0 == grid_x && (0 == grid_y || ((n - 1) == grid_y))) || ((n - 1) == grid_x && 0 == grid_y))
                {
                    continue;
                }
                size_t alignment_offset = qr_width * (size_t)(alignment_positions[grid_y] - 2) + (size_t)alignment_positions[grid_x] - 2;
                for (int row = 0; row < 5; ++row)
                {
                    for (size_t col = 0; col < 5; ++col)
                    {
                        qr_buffer.data[alignment_offset + col] = ((alignment_pattern[row] >> col) & 1) * 0xffu;
                    }
                    alignment_offset += qr_width;
                }
            }
        }
    }

    // Finder patterns
    const uint8_t finder_pattern[8] = {0x80u, 0xbeu, 0xa2u, 0xa2u, 0xa2u, 0xbeu, 0x80u, 0xffu};
    for (size_t row = 0; row < 8; ++row)
    {
        size_t finder_index = row * qr_width;
        for (size_t col = 0; col < 8; ++col)
        {
            qr_buffer.data[finder_index + col] = ((finder_pattern[row] >> col) & 1) * 0xffu;
        }
    }

    if (QR_SIZE_STANDARD == qr_type)
    {
        for (size_t row = 0; row < 8; ++row)
        {
            qr_buffer.data[qr_width * (row + 1) - 8] = 0xffu;
            memcpy(qr_buffer.data + qr_width * (row + 1) - 7, qr_buffer.data + qr_width * row, 7);
        }
        memcpy(qr_buffer.data + qr_width * (qr_width - 8), qr_buffer.data + qr_width * 7, 8);
        for (size_t row = 0; row < 7; ++row)
        {
            memcpy(qr_buffer.data + qr_width * (qr_width - 7 + row), qr_buffer.data + qr_width * row, 8);
        }
    }

    // // Format and version areas
    // for (size_t i = 0; i < 8; ++i)
    // {
    //     qr_buffer.data[8 + i * qr_width] = 0xffu;
    //     qr_buffer.data[8 + (qr_width - 8 + i) * qr_width] = 0xffu;
    //     qr_buffer.data[8 * qr_width + i] = 0xffu;
    //     qr_buffer.data[9 * qr_width - 8 + i] = 0xffu;
    // }
    // qr_buffer.data[8 + 8 * qr_width] = 0xffu;
    // if (version > 5)
    // {
    //     for (size_t i = 0; i < 6; ++i)
    //     {
    //         for (size_t j = 0; j < 3; ++j)
    //         {
    //             qr_buffer.data[(qr_width * (i + 1)) - 11 + j] = 0xffu;        // RHS top
    //             qr_buffer.data[(qr_width * (qr_width - 11 + j)) + i] = 0xffu; // LHS bottom
    //         }
    //     }
    // }

    // Timing Patterns
    if (QR_SIZE_MICRO == qr_type)
    {
        for (size_t i = 8; i < qr_width; ++i)
        {
            uint8_t val = (i & 1) * 0xffu;
            qr_buffer.data[i] = val;
            qr_buffer.data[i * qr_width] = val;
        }
    }
    if (QR_SIZE_STANDARD == qr_type)
    {
        size_t timing_pattern_offset = 6;
        size_t row_offset = qr_width * timing_pattern_offset;
        for (size_t i = 8; i < qr_width - 8; ++i)
        {
            uint8_t val = (i & 1) * 0xffu;
            qr_buffer.data[row_offset + i] = val;
            qr_buffer.data[i * qr_width + timing_pattern_offset] = val;
        }
    }

    // ================================================================
    // Data
    // ================================================================

    struct fill_settings_t fill_settings = {.qr_width = (int)qr_width};

    // 8 Mask patterns, if true switch the bit (XOR)
    if (QR_SIZE_MICRO == qr_type)
    {
        for (int c = 0; c < 12; c++)
        {
            for (int r = 0; r < 12; r++)
            {
                fill_settings.masks[r][c] = 0;
                fill_settings.masks[r][c] |= (r % 2 == 0) << 0;
                fill_settings.masks[r][c] |= (((r / 2) + (c / 3)) % 2 == 0) << 1; // Take floor of terms mod 2
                fill_settings.masks[r][c] |= (((r * c) % 2 + (r * c) % 3) % 2 == 0) << 2;
                fill_settings.masks[r][c] |= (((r + c) % 2 + (r * c) % 3) % 2 == 0) << 3;
            }
        }
    }
    else
    {
        for (int c = 0; c < 12; c++)
        {
            for (int r = 0; r < 12; r++)
            {
                fill_settings.masks[r][c] = 0;
                fill_settings.masks[r][c] |= ((r + c) % 2 == 0) << 0;
                fill_settings.masks[r][c] |= (r % 2 == 0) << 1;
                fill_settings.masks[r][c] |= (c % 3 == 0) << 2;
                fill_settings.masks[r][c] |= ((r + c) % 3 == 0) << 3;
                fill_settings.masks[r][c] |= (((r / 2) + (c / 3)) % 2 == 0) << 4; // Take floor of terms mod 2
                fill_settings.masks[r][c] |= ((r * c) % 2 + (r * c) % 3 == 0) << 5;
                fill_settings.masks[r][c] |= (((r * c) % 2 + (r * c) % 3) % 2 == 0) << 6;
                fill_settings.masks[r][c] |= (((r + c) % 2 + (r * c) % 3) % 2 == 0) << 7;
            }
        }
    }

    // Begin:   Fill rows [9 to last],      alignment symbols [1 to last]                               x4
    //          Fill rows [0 to last],      alignment symbols [1 to last], allow for version info       x2
    //          Fill rows [0 to last],      alignment symbols [0 to last]                               xN
    //          Fill rows [9 to last - 8],  alignment symbols [1 to last - 1]                           x1
    //          Fill rows [9 to last - 8],  alignment symbols [1 to last - 1], allow for version info   x3

    uint8_t *mask_buffer = malloc(qr_width * qr_width);
    struct buffer_t interleaved_buffer = {.byte_index = 0, .bit_index = 7, .data = interleaved_data, .size = qr_data_size};

    export_test("blank.ppm", (int)qr_width, 0, qr_buffer.data);
    if (QR_SIZE_MICRO == qr_type)
    {
        fill_settings.alignment.positions = NULL;
        fill_settings.alignment.size = 0;
        typedef void (*fill_fp)(struct buffer_t *const, const int, const int, const int, const int, const int, const struct fill_settings_t *const, uint8_t *const);
        fill_fp fill[2] = {fill_u, fill_d};
        int dir = 0;
        int col = (int)qr_width - 1;
        while (col > 8)
        {
            fill[dir](&interleaved_buffer, col, 1, (int)qr_width - 1, -1, -1, &fill_settings, qr_buffer.data);
            dir ^= 1;
            col -= 2;
        }
        while (col > 0)
        {
            fill[dir](&interleaved_buffer, col, 9, (int)qr_width - 1, -1, -1, &fill_settings, qr_buffer.data);
            dir ^= 1;
            col -= 2;
        }
    }
    else
    {
        fill_settings.alignment.positions = alignment_positions,
        fill_settings.alignment.size = n;
        fill_u(&interleaved_buffer, (int)qr_width - 1, 9, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer.data);
        fill_d(&interleaved_buffer, (int)qr_width - 3, 9, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer.data);
        fill_u(&interleaved_buffer, (int)qr_width - 5, 9, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer.data);
        fill_d(&interleaved_buffer, (int)qr_width - 7, 9, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer.data);

        fill_u(&interleaved_buffer, (int)qr_width - 9, 7, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer.data);
        if (version < 7)
        {
            fill_u(&interleaved_buffer, (int)qr_width - 9, 0, 5, 1, 1, &fill_settings, qr_buffer.data);
            fill_d(&interleaved_buffer, (int)qr_width - 11, 0, 5, 1, 1, &fill_settings, qr_buffer.data);
        }
        else
        {
            for (int i = 0; i < 6; ++i)
            {
                qr_buffer.data[(int)qr_width * i + (int)qr_width - 12] = read_bit_stream(&interleaved_buffer) ^ fill_settings.masks[i % 12][(qr_width - 12) % 12];
            }
        }
        fill_d(&interleaved_buffer, (int)qr_width - 11, 7, (int)qr_width - 1, 0, n - 1, &fill_settings, qr_buffer.data);

        for (int i = (int)qr_width - 13; i > 8; i -= 2)
        {
            if (0 == ((i >> 1) & 1))
            {
                fill_u(&interleaved_buffer, i, 7, (int)qr_width - 1, 0, n - 1, &fill_settings, qr_buffer.data);
                fill_u(&interleaved_buffer, i, 0, 5, 0, 0, &fill_settings, qr_buffer.data);
            }
            else
            {
                fill_d(&interleaved_buffer, i, 0, 5, 0, 0, &fill_settings, qr_buffer.data);
                fill_d(&interleaved_buffer, i, 7, (int)qr_width - 1, 0, n - 1, &fill_settings, qr_buffer.data);
            }
        }
        fill_u(&interleaved_buffer, 8, 9, (int)qr_width - 9, 1, n - 2, &fill_settings, qr_buffer.data);
        int version_offset = (version < 7) ? 9 : 12;
        fill_d(&interleaved_buffer, 5, 9, (int)qr_width - version_offset, 1, n - 2, &fill_settings, qr_buffer.data);
        fill_u(&interleaved_buffer, 3, 9, (int)qr_width - version_offset, 1, n - 2, &fill_settings, qr_buffer.data);
        printf("%lu %u %lu - %lu bits remaining in buffer, %lu required to fill\n", interleaved_buffer.byte_index, interleaved_buffer.bit_index, interleaved_buffer.size, ((interleaved_buffer.size - interleaved_buffer.byte_index - 1) << 3) + interleaved_buffer.bit_index + 1, (qr_width - (size_t)version_offset - 8) << 1);
        fill_d(&interleaved_buffer, 1, 9, (int)qr_width - version_offset, 1, n - 2, &fill_settings, qr_buffer.data);
    }

    // ================================================================
    // Mask Evaluation
    // ================================================================
    int mask_score = 0;
    uint8_t mask_pattern_index = 0;
    if (QR_SIZE_MICRO == qr_type)
    {
        for (int j = 0; j < 4; ++j)
        {
            int sum1 = 0;
            int sum2 = 0;
            for (size_t i = 1; i < qr_width; ++i)
            {
                int mask = (0x01 << j);
                sum1 += (qr_buffer.data[(i + 1) * qr_width - 1] & mask) == 0;
                sum2 += (qr_buffer.data[qr_width * qr_width - i] & mask) == 0;
            }
            int score = (sum1 > sum2) ? (sum2 << 4) + sum1 : (sum1 << 4) + sum2;
            if (score > mask_score)
            {
                mask_score = score;
                mask_pattern_index = (uint8_t)j;
            }
        }
    }
    else
    {
        struct mask_eval_t
        {
            struct
            {
                int last_module;
                int length;
            } run;
            struct
            {
                int pattern;
                int run;
                int block;
                int ratio;
            } score;
            int module_count;
            uint16_t pattern_buffer;
        } mask_eval[8];

        // Init
        for (int m = 0; m < 8; ++m)
        {
            mask_eval[m].module_count = 0;
            mask_eval[m].score.pattern = 0;
            mask_eval[m].score.run = 0;
            mask_eval[m].score.block = 0;
            mask_eval[m].score.ratio = 0;
        }

        // Evaluate rows
        for (size_t row = 0; row < qr_width; ++row)
        {
            // Init
            for (size_t m = 0; m < 8; ++m)
            {
                mask_eval[m].pattern_buffer = 0;
                mask_eval[m].run.last_module = 0;
                mask_eval[m].run.length = 0;
            }
            for (size_t col = 0; col < qr_width; ++col)
            {
                for (int m = 0; m < 8; ++m)
                {
                    size_t module = (qr_buffer.data[row * qr_width + col] >> m) & 1;
                    mask_eval[m].module_count += (int)module;                                                                     // N4
                    mask_eval[m].score.pattern += pattern_score((int)module, &mask_eval[m].pattern_buffer);                       // N3
                    mask_eval[m].score.run += repeat_score((int)module, &mask_eval[m].run.last_module, &mask_eval[m].run.length); // N1
                }
            }
            for (int m = 0; m < 8; ++m)
            {
                // N1 end of line check
                if (mask_eval[m].run.length >= 5)
                {
                    mask_eval[m].score.run += mask_eval[m].run.length - 2;
                }
            }
        }

        // Evaluate columns
        for (size_t col = 0; col < qr_width; ++col)
        {
            // Init
            for (size_t m = 0; m < 8; ++m)
            {
                mask_eval[m].pattern_buffer = 0;
                mask_eval[m].run.last_module = 0;
                mask_eval[m].run.length = 0;
            }
            uint8_t a = 0xffu; // a  b
            uint8_t b = ~a;    // c  d     Sampling for N2 evaluation
            for (size_t row = 0; row < qr_width; ++row)
            {
                uint8_t c = (0 == col) ? ~a : qr_buffer.data[row * qr_width + col - 1];
                uint8_t d = qr_buffer.data[row * qr_width + col];
                for (size_t m = 0; m < 8; ++m)
                {
                    int module = (d >> m) & 1;
                    mask_eval[m].score.pattern += pattern_score(module, &mask_eval[m].pattern_buffer);                       // N3
                    mask_eval[m].score.run += repeat_score(module, &mask_eval[m].run.last_module, &mask_eval[m].run.length); // N1

                    int module_a = (a >> m) & 1;
                    int module_b = (b >> m) & 1;
                    int module_c = (c >> m) & 1;
                    if (module == module_c && module_c == module_b && module_b == module_a) // N2
                    {
                        mask_eval[m].score.block += 3;
                    }
                }
                a = c;
                b = d;
            }
            for (int m = 0; m < 8; ++m)
            {
                // N1 end of line check
                if (mask_eval[m].run.length >= 5)
                {
                    mask_eval[m].score.run += mask_eval[m].run.length - 2;
                }
            }
        }

        for (int m = 0; m < 8; ++m) // N4 final score
        {
            int temp = abs((1000 * mask_eval[m].module_count) / (int)(qr_width * qr_width) - 500) / 50;
            mask_eval[m].score.ratio = temp * 10;
        }

        mask_score = mask_eval[0].score.block + mask_eval[0].score.pattern + mask_eval[0].score.ratio + mask_eval[0].score.run;
        printf("Mask 0: %d (%d %d %d %d)\n", mask_score, mask_eval[0].score.run, mask_eval[0].score.block, mask_eval[0].score.pattern, mask_eval[0].score.ratio);
        mask_pattern_index = 0;
        for (int i = 1; i < 8; ++i)
        {
            int score = mask_eval[i].score.block + mask_eval[i].score.pattern + mask_eval[i].score.ratio + mask_eval[i].score.run;
            printf("Mask %01x: %d (%d %d %d %d)\n", i, score, mask_eval[i].score.run, mask_eval[i].score.block, mask_eval[i].score.pattern, mask_eval[i].score.ratio);
            if (score < mask_score)
            {
                mask_score = score;
                mask_pattern_index = (uint8_t)i;
            }
        }
    }
    printf("Mask: %u (%d)\n", mask_pattern_index, mask_score);

    // ================================================================
    // Format
    // ================================================================
    uint16_t format_data;
    if (QR_SIZE_MICRO == qr_type)
    {
        uint16_t version_indicators[] = {0, 1, 3, 5};
        format_data = version_indicators[version];
        switch (correction_level)
        {
        case CORRECTION_LEVEL_M:
            format_data += 1;
            break;
        case CORRECTION_LEVEL_Q:
            format_data += 2;
            break;
        default:
            break;
        }
        format_data <<= 12;
        format_data |= (uint16_t)(mask_pattern_index << 10);
    }
    else
    {
        format_data = (uint16_t)(correction_level << 13) | (uint16_t)(mask_pattern_index << 10);
    }

    uint16_t format = format_data;
    uint16_t format_generator = BCH_GENERATOR << 4;
    uint16_t format_mask = 0x4000;
    while (format_mask > 0x0200)
    {
        if (format_mask & format)
        {
            format ^= format_generator;
        }
        format_generator >>= 1;
        format_mask >>= 1;
    }
    format |= format_data;
    format ^= (QR_SIZE_MICRO == qr_type) ? MICRO_QR_FORMAT_MASK : QR_FORMAT_MASK;
    printf("Format/Mask: 0x%04x (15 bits)\n", format);
    if (QR_SIZE_MICRO == qr_type)
    {
        size_t function_offset = qr_width + 8;
        for (size_t i = 0; i < 7; ++i)
        {
            qr_buffer.data[function_offset] = (uint8_t)~(((format >> i) & 1) * 0xffu);
            function_offset += qr_width;
        }
        for (size_t i = 7; i < 15; ++i)
        {
            qr_buffer.data[function_offset] = (uint8_t)~(((format >> i) & 1) * 0xffu);
            --function_offset;
        }
    }
    else
    {
        size_t function_offset = 8 * qr_width;
        for (size_t i = 0; i < 6; ++i)
        {
            qr_buffer.data[function_offset + i] = (uint8_t)~(((format >> (14 - i)) & 1) * 0xffu);
        }
        qr_buffer.data[function_offset + 7] = (uint8_t)~(((format >> 8) & 1) * 0xffu);
        qr_buffer.data[function_offset + 8] = (uint8_t)~(((format >> 7) & 1) * 0xffu);
        for (int i = 7; i >= 0; --i)
        {
            qr_buffer.data[function_offset + qr_width - 1 - (size_t)i] = (uint8_t)~(((format >> i) & 1) * 0xffu);
        }

        for (size_t i = 0; i < 6; ++i)
        {
            qr_buffer.data[i * qr_width + 8] = (uint8_t)~(((format >> i) & 1) * 0xffu);
        }
        qr_buffer.data[7 * qr_width + 8] = (uint8_t)~(((format >> 6) & 1) * 0xffu);
        qr_buffer.data[(qr_width - 8) * qr_width + 8] = 0;
        for (size_t i = 7; i > 0; --i)
        {
            qr_buffer.data[(qr_width - i) * qr_width + 8] = (uint8_t)~(((format >> (15 - i)) & 1) * 0xffu);
        }
    }

    // ================================================================
    // Version
    // ================================================================

    if (version > 5)
    {
        uint32_t version_code = (uint32_t)((version + 1) << 12);
        uint32_t version_generator = GOLAY_GENERATOR << 5;
        uint32_t version_mask = 0x00020000U;
        while (version_mask > 0x00000800U)
        {
            if (version_mask & version_code)
            {
                version_code ^= version_generator;
            }
            version_generator >>= 1;
            version_mask >>= 1;
        }
        version_code |= ((uint32_t)version + 1) << 12;
        printf("Version: 0x%06x (18 bits)\n", version_code);
        for (size_t i = 0; i < 6; ++i)
        {
            for (size_t j = 0; j < 3; ++j)
            {
                qr_buffer.data[(qr_width - 11) + i * qr_width + j] = (uint8_t)~(((version_code >> ((i * 3) + j)) & 1) * 0xffu);
                qr_buffer.data[qr_width * ((qr_width - 1) - 10 + j) + i] = (uint8_t)~(((version_code >> ((i * 3) + j)) & 1) * 0xffu);
            }
        }
    }
    // export_test("qr.ppm", (int)qr_width, mask_pattern_index, qr_buffer.data);

    // ================================================================
    // Output
    // ================================================================

    size_t output_struct_size = sizeof(struct qr_data_t);
    size_t output_data_size = (size_t)(qr_width * qr_width + 0x07) >> 3;
    void *output_buffer = calloc(output_struct_size + output_data_size, sizeof(uint8_t));
    struct qr_data_t *qr_code = (struct qr_data_t *)output_buffer;
    qr_code->err_level = correction_level;
    qr_code->version = version + VERSION_OFFSET;
    qr_code->width = (int)qr_width;
    qr_code->mask = mask_pattern_index;
    qr_code->data = (uint8_t *)output_buffer + output_struct_size;

    struct buffer_t output_builder = {.bit_index = 0, .byte_index = 0, .data = qr_code->data};
    for (size_t i = 0; i < qr_width * qr_width; ++i)
    {
        if (output_builder.bit_index > 7)
        {
            output_builder.bit_index = 0;
            ++output_builder.byte_index;
        }
        output_builder.data[output_builder.byte_index] |= ((qr_buffer.data[i] >> mask_pattern_index) & 1) << (7 - output_builder.bit_index);
        ++output_builder.bit_index;
    }

    free(mask_buffer);
    free(qr_buffer.data);
    free(interleaved_data);
    free(encoder_buffer.data);
    free(final_list);
    free(encoding_list);
    return qr_code;
}
