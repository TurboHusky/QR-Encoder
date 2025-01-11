#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#define VERSION_OFFSET 1
#define VERSION_UNDEFINED -1
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
#define TIMING_ROW 6

#define EVAL_PATTERN_MASK 0x07ff
#define EVAL_PATTERN_LEFT 0x07a2
#define EVAL_PATTERN_RIGHT 0x022f

#define QR_FORMAT_MASK 0x5412
#define MICRO_QR_FORMAT_MASK 0X4445
#define BCH_GENERATOR 0x0537
#define GOLAY_GENERATOR 0x1f25

#define BLOCK_TYPE_BIT_COUNT 4
#define CHAR_COUNT_LOW_LIMIT 9
#define CHAR_COUNT_UPPER_LIMIT 26

enum error_correction_level_t
{
    err_L = 0x01, //  7%
    err_M = 0x00, // 15%
    err_Q = 0x03, // 25%
    err_H = 0x02  // 30%
};

struct qr_data_t
{
    enum error_correction_level_t err_level;
    int version;
    int width;
    int mask;
    uint8_t *data;
};

enum encoding_mode_t
{
    enc_numeric,
    enc_alpha_numeric,
    enc_byte, // latin1
    enc_kanji,
    enc_eci,
    enc_structured_append,
    enc_FNC1_1,
    enc_FNC1_2,
    enc_unsupported
};

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

const char alphanumeric_lookup[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    36, 0, 0, 0, 37, 38, 0, 0, 0, 0, 39, 40, 0, 41, 42, 43,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 44, 0, 0, 0, 0, 0,
    0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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
        buffer->data[buffer->byte_index] |= data >> (8 + buffer->bit_index);
        data <<= filled;
        bitcount -= filled;
        buffer->bit_index += filled;
        buffer->byte_index += (buffer->bit_index & 0x08) >> 3;
        buffer->bit_index &= 0x07;
    }
}

uint8_t read_bit_stream(struct buffer_t *const buffer)
{
    uint8_t result = (buffer->data[buffer->byte_index] >> buffer->bit_index) & 1;
    --buffer->bit_index;
    buffer->bit_index &= 0x07;
    buffer->byte_index += (buffer->bit_index + 1) >> 3;
    return ~(result * 0xff);
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
            buffer[0] = buffer[1] = buffer[2] = (data[r * qr_width + c] >> bit_offset) & 0x01;
            fwrite(&buffer, 3, 1, test);
        }
    }
    fclose(test);
}

void export_as_ppm(const int qr_width, const uint8_t *const data)
{
    FILE *test_output;
    test_output = fopen("qr.ppm", "wb");
    int quiet = 4;
    fprintf(test_output, "P6 %d %d 1\n", qr_width + (2 * quiet), qr_width + (2 * quiet));
    uint8_t buffer[3] = {0x01, 0x01, 0x01};

    int bit_idx = 7;
    int byte_idx = 0;

    for (int i = 0; i < (quiet * (qr_width + 9)); ++i)
    {
        fwrite(&buffer, sizeof(buffer), 1, test_output);
    }
    for (int r = 0; r < qr_width; r++)
    {
        for (int c = 0; c < qr_width; c++)
        {
            if (bit_idx < 0)
            {
                bit_idx = 7;
                ++byte_idx;
            }
            buffer[0] = buffer[1] = buffer[2] = (data[byte_idx] >> bit_idx) & 0x01;
            fwrite(&buffer, 3, 1, test_output);
            --bit_idx;
        }
        buffer[0] = buffer[1] = buffer[2] = 0x01;
        for (int i = 0; i < (2 * quiet); ++i)
            fwrite(&buffer, sizeof(buffer), 1, test_output);
    }
    for (int i = 0; i < (quiet * (qr_width + 7)); ++i)
    {
        fwrite(&buffer, sizeof(buffer), 1, test_output);
    }
    fclose(test_output);
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

        int bits = ('0' == a) ? ('0' == b) ? 4 : 7 : 10;
        uint16_t encoded = (a - '0') * 100 + (b - '0') * 10 + (c - '0');

        printf("%c %c %c -> %04x %u bits\n", a, b, c, encoded, bits);
        add_to_buffer(encoded, bits, output);

        index += 3;
    }

    switch (input.size - index)
    {
    case 2:
        printf("7 residual bits\n");
        add_to_buffer((input.data[index] - '0') * 10 + input.data[index + 1] - '0', 7, output);
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
    size_t index = 0;

    while (index < input.size - 1)
    {
        uint16_t code = 45 * (uint16_t)alphanumeric_lookup[input.data[index]] + (uint16_t)alphanumeric_lookup[input.data[index + 1]];
        add_to_buffer(code, 11, output);
        index += 2;
    }

    if (index < input.size)
    {
        uint16_t code = (uint16_t)alphanumeric_lookup[input.data[index]];
        add_to_buffer(code, 6, output);
    }
}

uint16_t encode_kanji(const char a, const char b)
{
    uint16_t offset = 0x8140;
    uint16_t in = (uint16_t)(((uint8_t)a << 8) | (uint8_t)b);
    if (in >= 0xE040 && in <= 0xEBBF)
    {
        offset = 0xC140;
    }
    else if (in < 0x8140 || in > 0x9FFC)
    {
        return 0;
    }

    in -= offset;
    uint8_t msb = in >> 8;
    in &= 0x00FF;
    return msb * 0xC0 + in;
}

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
    // printf("%d: %lu bits\n", version, free_modules);
    return free_modules;
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
    case enc_numeric:
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
    case enc_alpha_numeric:
        length_bits = (version < CHAR_COUNT_LOW_LIMIT) ? 9 : (version < CHAR_COUNT_UPPER_LIMIT) ? 11
                                                                                                : 13;
        data_bits -= length_bits;
        remainder = data_bits % 11;
        char_count = (data_bits / 11) * 2;
        char_count += (remainder >= 6) ? 1 : 0;
        break;
    case enc_byte:
        length_bits = (version < CHAR_COUNT_LOW_LIMIT) ? 8 : 16;
        data_bits -= length_bits;
        char_count = data_bits >> 3;
        break;
    case enc_kanji:
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

struct limits_t
{
    int qr_width;
    int row_min;
    int row_max;
    int align_col_index;
    int align_index_min;
    int align_index_max;
    const int *const alignment_positions;
};

void fill_up(const int column, const struct limits_t limits, struct buffer_t *const input_data, const uint8_t masks[12][12], uint8_t *const output)
{
    int offset = (limits.row_max * limits.qr_width) + column;
    for (int row = limits.row_max; row >= limits.row_min; --row)
    {
        if (row != TIMING_ROW)
        {
            output[offset] = read_bit_stream(input_data) ^ masks[row % 12][column % 12];
            output[offset - 1] = read_bit_stream(input_data) ^ masks[row % 12][(column - 1) % 12];
        }
        offset -= limits.qr_width;
    }
}

void fill_down(const int column, const struct limits_t limits, struct buffer_t *const input_data, const uint8_t masks[12][12], uint8_t *const output)
{
    int offset = (limits.row_min * limits.qr_width) + column;
    for (int row = limits.row_min; row <= limits.row_max; ++row)
    {
        if (row != TIMING_ROW)
        {
            output[offset] = read_bit_stream(input_data) ^ masks[row % 12][column % 12];
            output[offset - 1] = read_bit_stream(input_data) ^ masks[row % 12][(column - 1) % 12];
        }
        offset += limits.qr_width;
    }
}

void align_up(const int column, const struct limits_t limits, struct buffer_t *const input_data, const uint8_t masks[12][12], uint8_t *const output)
{
    int offset = (limits.row_max * limits.qr_width) + column;
    int alignment_row_index = limits.align_index_max;

    while (alignment_row_index >= limits.align_index_min && limits.row_max < limits.alignment_positions[alignment_row_index] - ALIGNMENT_PATTERN_OFFSET)
    {
        --alignment_row_index;
    }

    for (int row = limits.row_max; row >= limits.row_min; --row)
    {
        if (row != TIMING_ROW)
        {
            if (alignment_row_index >= limits.align_index_min && row < limits.alignment_positions[alignment_row_index] - ALIGNMENT_PATTERN_OFFSET)
            {
                --alignment_row_index;
            }
            if (alignment_row_index >= limits.align_index_min && row <= limits.alignment_positions[alignment_row_index] + ALIGNMENT_PATTERN_OFFSET)
            {
                if ((column - 1) < limits.alignment_positions[limits.align_col_index] - ALIGNMENT_PATTERN_OFFSET)
                {
                    output[offset - 1] = read_bit_stream(input_data) ^ masks[row % 12][(column - 1) % 12];
                }
            }
            else
            {
                output[offset] = read_bit_stream(input_data) ^ masks[row % 12][column % 12];
                output[offset - 1] = read_bit_stream(input_data) ^ masks[row % 12][(column - 1) % 12];
            }
        }
        offset -= limits.qr_width;
    }
}

void align_down(const int column, const struct limits_t limits, struct buffer_t *const input_data, const uint8_t masks[12][12], uint8_t *const output)
{
    int offset = (limits.row_min * limits.qr_width) + column;
    int alignment_row_index = limits.align_index_min;

    while (alignment_row_index <= limits.align_index_max && limits.row_min > limits.alignment_positions[alignment_row_index] + ALIGNMENT_PATTERN_OFFSET)
    {
        ++alignment_row_index;
    }

    for (int row = limits.row_min; row <= limits.row_max; ++row)
    {
        if (row != TIMING_ROW)
        {
            if (alignment_row_index <= limits.align_index_max && row > limits.alignment_positions[alignment_row_index] + ALIGNMENT_PATTERN_OFFSET)
            {
                ++alignment_row_index;
            }
            if (alignment_row_index <= limits.align_index_max && row >= limits.alignment_positions[alignment_row_index] - ALIGNMENT_PATTERN_OFFSET)
            {
                if ((column - 1) < limits.alignment_positions[limits.align_col_index] - ALIGNMENT_PATTERN_OFFSET)
                {
                    output[offset - 1] = read_bit_stream(input_data) ^ masks[row % 12][(column - 1) % 12];
                }
            }
            else
            {
                output[offset] = read_bit_stream(input_data) ^ masks[row % 12][column % 12];
                output[offset - 1] = read_bit_stream(input_data) ^ masks[row % 12][(column - 1) % 12];
            }
        }
        offset += limits.qr_width;
    }
}

int pattern_score(const int module, uint16_t *const buffer)
{
    *buffer <<= 1;
    *buffer |= module;
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

void calculate_error_codes(const int block_count, const int error_word_count, const uint8_t (*const gf256_lookup)[2], const int generator_start, const int generator_end, const uint8_t *const generator, const uint8_t *const input, uint8_t *error_words)
{
    printf("(%d:%d)\t", block_count, error_word_count);
    if (block_count < error_word_count)
    {
        memcpy(error_words, input, block_count);
        memset(error_words + block_count, 0, error_word_count - block_count);
    }
    else
    {
        memcpy(error_words, input, error_word_count);
    }

    for (int j = 0; j < block_count; ++j)
    {
        uint8_t temp;
        uint8_t gen_mult = gf256_lookup[error_words[0]][GF256_ANTILOG_INDEX]; // Generator multiplication factor
        for (size_t k = 1; k < (size_t)error_word_count; ++k)
        {
            // Multiply generator by leading term in data polynomial (add antilogs mod 255)
            temp = (gen_mult + gf256_lookup[generator[generator_start + k]][GF256_ANTILOG_INDEX]) % 255;
            // Add generator to data polynomial (XOR to cancel leading term)
            error_words[k - 1] = gf256_lookup[temp][GF256_LOG_INDEX] ^ error_words[k];
        }
        temp = (gen_mult + gf256_lookup[generator[generator_end]][GF256_ANTILOG_INDEX]) % 255;
        if (j + error_word_count < block_count)
        {
            error_words[error_word_count - 1] = gf256_lookup[temp][GF256_LOG_INDEX] ^ input[j + error_word_count];
        }
        else
        {
            error_words[error_word_count - 1] = gf256_lookup[temp][GF256_LOG_INDEX];
        }
    }
    for (int j = 0; j < error_word_count; ++j)
    {
        printf("%d ", error_words[j]);
    }
    printf("\n");
}

int parse_version(const char *const input)
{
    size_t input_size = strlen(input);
    if (1 == input_size && input[0] >= '0' && input[0] <= '9')
    {
        return input[0] - '0';
    }
    else if (2 == input_size && input[0] >= '0' && input[0] <= '9' && input[1] >= '0' && input[1] <= '9')
    {
        return 10 * (input[0] - '0') + input[1] - '0';
    }
    return VERSION_UNDEFINED;
}

struct user_params_t
{
    int version;
    enum error_correction_level_t correction_level;
};

int parse_qr_input(const int argc, const char *const *const argv, struct user_params_t *user_settings)
{
    user_settings->version = VERSION_UNDEFINED;
    user_settings->correction_level = err_M;

    if (argc < 2)
    {
        printf("No input data provided\n");
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; ++i)
    {
        if ('-' == argv[i][0])
        {
            size_t arg_size = strlen(argv[i]);
            if (1 == arg_size)
            {
                printf("Invalid argument\n");
                return EXIT_FAILURE;
            }
            if (3 == arg_size && 0 == strncmp(argv[i], "--h", 3) || 6 == arg_size && 0 == strncmp(argv[i], "--help", 6))
            {
                printf("Usage: qr [-v] [-lLmMqQhH] [-h | --help] SOURCE\n\n\t--h,--help\tPrint help\n\t-v\t\tSet version 1-40\n\t-l,-L\t\terror correction 7%%\n\t-m,-M\t\terror correction 15%%\n\t-q,-Q\t\terror correction 25%%\n\t-h,-H\t\terror correction 30%%\n");
                return EXIT_FAILURE;
            }

            switch (argv[i][1])
            {
            case 'v':
                if (2 == arg_size)
                {
                    ++i;
                    if (i >= argc - 1)
                    {
                        printf("Missing version argument\n");
                        return EXIT_FAILURE;
                    }
                    user_settings->version = parse_version(argv[i]);
                }
                else
                {
                    user_settings->version = parse_version(argv[i] + 3);
                }
                if (user_settings->version < (VERSION_MIN + VERSION_OFFSET) || user_settings->version > (VERSION_MAX + VERSION_OFFSET))
                {
                    printf("Invalid version\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'l':
            case 'L':
                user_settings->correction_level = err_L;
                break;
            case 'm':
            case 'M':
                break;
            case 'q':
            case 'Q':
                user_settings->correction_level = err_Q;
                break;
            case 'h':
            case 'H':
                user_settings->correction_level = err_H;
                break;
            default:
                printf("Invalid option\n");
                return EXIT_FAILURE;
                break;
            }
        }
        else if (i != argc - 1)
        {
            printf("Unrecognised input option\n");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

struct qr_data_t *qr_encode(const int qr_version, const enum error_correction_level_t correction_level, const char *const data)
{
    struct buffer_t input;
    input.size = strlen(data);
    input.data = (uint8_t *)data;

    // ================================================================
    // Check input data type and QR version
    // ================================================================

    size_t index = 0;
    enum encoding_mode_t mode = enc_numeric;
    const uint8_t mode_indicators[9] = {0x01, 0x02, 0x04, 0x08, 0x07, 0x03, 0x05, 0x09, 0x0f}; // Matches encoding_mode_t order
    while (index < input.size)
    {
        uint8_t b = input.data[index];
        if (b < '0' || b > '9')
        {
            mode = enc_alpha_numeric;
            break;
        }
        ++index;
    }
    while (index < input.size)
    {
        uint8_t b = input.data[index];
        if ((b < '-' && b != ' ' && b != '$' && b != '%' && b != '*' && b != '+') || b > 'Z' || (b > ':' && b < 'A'))
        {
            mode = enc_byte;
            break;
        }
        ++index;
    }
    while (index < input.size)
    {
        // check for ~ddd pattern for Latin1 codes
        unsigned char b = input.data[index];
        if (b < 0x20 || (b > 0x7E && b < 0xA0))
        {
            mode = enc_kanji;
            break;
        }
        ++index;
    }

    // kanji mode uses Shift JIS encoding, can only encode 2 byte characters (Full Shift JIS scheme has single character and ASCII support)
    // 0x20 - 0x7E ASCII with 0x5C and 0x 7E modiified
    // 0xA1 - 0xAF Single byte half-width katakana
    // 0x81 - 0x9F and 0xE0 - 0xEF First byte of double byte JIS X 0208
    // 0x40 - 0x9E (excluding 0x7F) Second byte (odd)
    // 0x9F - 0xFC Second byte (even)
    if (enc_kanji == mode)
    {
        if (input.size & 0x01)
        {
            // Kanji is always 2 bytes?
            mode = enc_unsupported;
            return NULL;
        }
        else
        {
            for (size_t i = 0; i < input.size; i += 2)
            {
                uint16_t kana = (uint16_t)(input.data[i] << 8 | input.data[i + 1]);
                // This check is not accurate
                if (kana < 0x8140 || kana > 0xEBBF || (kana > 0x9FCC && kana < 0xE040))
                {
                    mode = enc_unsupported;
                    printf("Unsupported data type");
                    return NULL;
                }
            }
        }
    }

    // Version 1 -> 21 x 21, Version 40 -> 177, 177
    // --------------------------------------------

    // Base size W x H                          e.g. 21 x 21 = 441 px
    // Finders 3 x 7 x 7
    // Separators 3 x 15
    // Dark + Format 1 + 30                     Total fixed modules: 223
    // Version 18 + 18                          Versions 7+
    // Alignment (n x n - 3) x 25               Versions 2+
    // Timing (W + H - 32) - ((n - 2) x 2) x 5

    int version;
    int input_capacity;
    if (VERSION_UNDEFINED == qr_version)
    {
        version = VERSION_MAX;
        input_capacity = calculate_capacity(version, (int)correction_level, mode);

        // Get smallest compatible version
        while (version > 0)
        {
            int next_lowest_capacity = calculate_capacity(version - 1, (int)correction_level, mode);
            if (input.size > (size_t)next_lowest_capacity)
            {
                break;
            }
            input_capacity = next_lowest_capacity;
            --version;
        }
    }
    else if (qr_version < (VERSION_MIN + VERSION_OFFSET) || qr_version > (VERSION_MAX + VERSION_OFFSET))
    {
        printf("Invalid QR version specified\n");
        return NULL;
    }
    else
    {
        version = qr_version - VERSION_OFFSET;
        input_capacity = calculate_capacity(version, (int)correction_level, mode);
    }
    if (input.size > (size_t)input_capacity)
    {
        printf("Data exceeds QR code capacity\n");
        return NULL;
    }

    int qr_width = 21 + (version << 2);
    int module_total = qr_width * qr_width;
    int alignment_positions[ALIGNMENT_POSITIONS_MAX];
    const int n = compute_alignment_positions(version + VERSION_OFFSET, alignment_positions);
    const int(*block_data)[5] = &error_blocks[version][correction_level];
    const size_t data_bytes = (size_t)((*block_data)[GROUP_1_BLOCK_COUNT] * (*block_data)[GROUP_1_BLOCK_SIZE] + (*block_data)[GROUP_2_BLOCK_COUNT] * (*block_data)[GROUP_2_BLOCK_SIZE]);
    const size_t error_bytes = (size_t)((*block_data)[ERR_WORDS_PER_BLOCK] * ((*block_data)[GROUP_1_BLOCK_COUNT] + (*block_data)[GROUP_2_BLOCK_COUNT]));

    char correction_map[] = {'M', 'L', 'H', 'Q'};
    printf("%ld input chars, Version: %d (%dx%d), modules: %d, correction level: %c, mode: %d, capacity: %d\n", input.size, version + VERSION_OFFSET, qr_width, qr_width, qr_size(version + 1, n), correction_map[correction_level], mode, input_capacity);
    printf("%ld data words, %ld error words\n", data_bytes, error_bytes);

    // ================================================================
    // Format input data
    // ================================================================

    // Extended Channel Interpretation (ECI)
    // Data stream consists of one or more segments
    // Each segment is in a separate mode
    // Default ECI the bit stream commences with the first mode indicator
    // An other ECI commences with an ECI header, followed by the first segment
    // ECI Header:
    //		- ECI mode indicator (4 bits, 0111)
    //		- ECI designator (8,16 or 24 bits - Identified by first zero in leading bits, i.e. 0, 10,110)
    // Segment:
    //		- Mode indicator
    //		- Char count
    //		- Data bit stream

    uint16_t char_count = 0;
    switch (mode)
    {
    case enc_numeric:
        char_count = (version < CHAR_COUNT_LOW_LIMIT) ? 10 : (version < CHAR_COUNT_UPPER_LIMIT) ? 12
                                                                                                : 14;
        break;
    case enc_alpha_numeric:
        char_count = (version < CHAR_COUNT_LOW_LIMIT) ? 9 : (version < CHAR_COUNT_UPPER_LIMIT) ? 11
                                                                                               : 13;
        break;
    case enc_byte:
        char_count = (version < CHAR_COUNT_LOW_LIMIT) ? 8 : 16;
        break;
    case enc_kanji:
        char_count = (version < CHAR_COUNT_LOW_LIMIT) ? 8 : (version < CHAR_COUNT_UPPER_LIMIT) ? 10
                                                                                               : 12;
        break;
    default:
        printf("Unexpected encoding mode encountered\n");
        return NULL;
        break;
    }

    struct buffer_t encoded = {.bit_index = 0, .byte_index = 0, .size = data_bytes + error_bytes};
    encoded.data = calloc(encoded.size, sizeof(*encoded.data));
    // 4 bit mode
    add_to_buffer(mode_indicators[mode], 4, &encoded);
    // N bit character count
    add_to_buffer((uint16_t)input.size, char_count, &encoded);

    // encode data
    // -----------
    switch (mode)
    {
    case enc_numeric:
        encode_numeric(input, &encoded);
        break;
    case enc_alpha_numeric:
        encode_alphanumeric(input, &encoded);
        break;
    case enc_byte:
        for (size_t i = 0; i < input.size; ++i)
        {
            add_to_buffer(input.data[i], 8, &encoded);
        }
        break;
    case enc_kanji:
        encode_kanji('a', 'b');
        break;
    case enc_eci:
    default:
        break;
    }

    // Terminator is up to 4 bits long
    // If still less that 8, pad with additional zeros
    // If empty bytes, append alternating pad bytes
    add_to_buffer(0, 4, &encoded); // Terminator

    encoded.byte_index += (encoded.bit_index + 0x07) >> 3;
    encoded.bit_index = 0;
    uint8_t pad_byte = 0xEC;
    while (encoded.byte_index < encoded.size)
    {
        encoded.data[encoded.byte_index] = pad_byte;
        pad_byte ^= 0xFD;
        ++encoded.byte_index;
    }

    // Expected encodings for the following inputs:
    // 1-Q: "HELLO WORLD" - 20 5b 0b 78 d1 72 dc 4d 43 40 ec 11 ec
    // 5-Q: "There\'s a frood who really knows where his towel is." - 43 55 46 86 57 26 55 c2 77 32 06 12 06 67 26 f6 f6 42 07 76 86 f2 07 26 56 16 c6 c7 92 06 b6 e6 f7 77 32 07 76 86 57 26 52 06 86 97 32 07 46 f7 76 56 c2 06 97 32 e0 ec 11 ec 11 ec 11 ec
    // 5-Q: "There\'s a frood who really knows where his towel is!" - 43 55 46 86 57 26 55 c2 77 32 06 12 06 67 26 f6 f6 42 07 76 86 f2 07 26 56 16 c6 c7 92 06 b6 e6 f7 77 32 07 76 86 57 26 52 06 86 97 32 07 46 f7 76 56 c2 06 97 32 10 ec 11 ec 11 ec 11 ec
    printf("Encoded input: ");
    for (size_t i = 0; i < data_bytes; ++i)
    {
        printf("%d ", encoded.data[i]);
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
    int generator_exponent = 7;
    uint8_t generator[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 127, 122, 154, 164, 11, 68, 117};
    int generator_end = sizeof(generator) - 1;
    int new_generator_exponent = (*block_data)[ERR_WORDS_PER_BLOCK];

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

    int generator_size = generator_exponent + 1;
    int generator_start = sizeof(generator) - generator_size;

    printf("Generator exponent: %d (%d terms)\n", generator_exponent, generator_size);
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
    uint8_t *error_words = encoded.data + data_bytes;

    size_t offset_ = 0;
    size_t err_offset = 0;
    for (int i = 0; i < (*block_data)[GROUP_1_BLOCK_COUNT]; ++i)
    {
        printf("Group 1, Block %d ", i + 1);
        calculate_error_codes((*block_data)[GROUP_1_BLOCK_SIZE], (*block_data)[ERR_WORDS_PER_BLOCK], gf256_lookup, generator_start, generator_end, generator, encoded.data + offset_, error_words + err_offset);
        offset_ += (*block_data)[GROUP_1_BLOCK_SIZE];
        err_offset += (*block_data)[ERR_WORDS_PER_BLOCK];
    }
    for (int i = 0; i < (*block_data)[GROUP_2_BLOCK_COUNT]; ++i)
    {
        printf("Group 2, Block %d ", i + 1);
        calculate_error_codes((*block_data)[GROUP_2_BLOCK_SIZE], (*block_data)[ERR_WORDS_PER_BLOCK], gf256_lookup, generator_start, generator_end, generator, encoded.data + offset_, error_words + err_offset);
        offset_ += (*block_data)[GROUP_2_BLOCK_SIZE];
        err_offset += (*block_data)[ERR_WORDS_PER_BLOCK];
    }

    // ================================================================
    // Patterns
    // ================================================================

    // Interleave data words
    struct buffer_t interleaved = {
        .bit_index = 0,
        .byte_index = 0,
        .size = (qr_size(version + 1, n) + 0x07) >> 3};
    interleaved.data = calloc(interleaved.size, sizeof(uint8_t));
    int line_index = 0;
    printf("Interleaved data: ");
    while (line_index < (*block_data)[GROUP_1_BLOCK_SIZE] || line_index < (*block_data)[GROUP_2_BLOCK_SIZE])
    {
        if (line_index < (*block_data)[GROUP_1_BLOCK_SIZE])
        {
            for (int i = 0; i < (*block_data)[GROUP_1_BLOCK_COUNT]; ++i)
            {
                interleaved.data[interleaved.byte_index] = encoded.data[i * (*block_data)[GROUP_1_BLOCK_SIZE] + line_index];
                printf("%d ", interleaved.data[interleaved.byte_index]);
                ++interleaved.byte_index;
            }
        }
        if (line_index < (*block_data)[GROUP_2_BLOCK_SIZE])
        {
            for (int i = 0; i < (*block_data)[GROUP_2_BLOCK_COUNT]; ++i)
            {
                interleaved.data[interleaved.byte_index] = encoded.data[((*block_data)[GROUP_1_BLOCK_COUNT] * (*block_data)[GROUP_1_BLOCK_SIZE]) + i * (*block_data)[GROUP_2_BLOCK_SIZE] + line_index];
                printf("%d ", interleaved.data[interleaved.byte_index]);
                ++interleaved.byte_index;
            }
        }
        ++line_index;
    }

    // Interleave error words
    int num_error_code_blocks = (*block_data)[GROUP_1_BLOCK_COUNT] + (*block_data)[GROUP_2_BLOCK_COUNT];
    for (int i = 0; i < (*block_data)[ERR_WORDS_PER_BLOCK]; ++i)
    {
        for (int j = 0; j < num_error_code_blocks; ++j)
        {
            interleaved.data[interleaved.byte_index] = error_words[i + j * (*block_data)[ERR_WORDS_PER_BLOCK]];
            printf("%d ", interleaved.data[interleaved.byte_index]);
            ++interleaved.byte_index;
        }
    }
    printf("\n");

    struct buffer_t qr_buffer = {.bit_index = 0, .byte_index = 0, .size = module_total};
    qr_buffer.data = malloc(qr_buffer.size);

    // Alignment Patterns
    const uint8_t alignment_pattern[5] = {0xe0, 0xee, 0xea, 0xee, 0xe0};
    for (int a = 0; a < n; ++a)
    {
        for (int i = 0; i < 5; ++i)
        {
            for (int b = 0; b < n; ++b)
            {
                if (((a == n - 1) && 0 == b) || (0 == a) && ((0 == b) || (b == n - 1)))
                {
                    continue;
                }
                int alignment_offset = qr_width * (alignment_positions[a] + i - 2) + alignment_positions[b] - 2;
                for (int j = 0; j < 5; ++j)
                {
                    qr_buffer.data[alignment_offset] = ((alignment_pattern[i] >> j) & 1) * 0xff;
                    ++alignment_offset;
                }
            }
        }
    }

    // Finder patterns
    const uint8_t finder_pattern[8] = {0x80, 0xbe, 0xa2, 0xa2, 0xa2, 0xbe, 0x80, 0x7f};
    for (int i = 0; i < 8; ++i)
    {
        int finder_index = i * qr_width;
        for (int j = 0; j < 7; ++j)
        {
            qr_buffer.data[finder_index + j] = ((finder_pattern[i] >> j) & 1) * 0xff;
        }
        qr_buffer.data[finder_index + 7] = 0xff;
    }
    for (int i = 0; i < 8; ++i)
    {
        qr_buffer.data[qr_width * (i + 1) - 8] = 0xff;
        memcpy(qr_buffer.data + qr_width * (i + 1) - 7, qr_buffer.data + qr_width * i, 7);
    }
    memcpy(qr_buffer.data + qr_width * (qr_width - 8), qr_buffer.data + qr_width * 7, 8);
    for (int i = 0; i < 7; ++i)
    {
        memcpy(qr_buffer.data + qr_width * (qr_width - 7 + i), qr_buffer.data + qr_width * i, 8);
    }

    // Format and version areas
    for (int i = 0; i < 9; ++i)
    {
        qr_buffer.data[qr_width * 8 + i] = 0xff;
        qr_buffer.data[qr_width * 9 - 1 - i] = 0xff;
        qr_buffer.data[8 + i * qr_width] = 0xff;
        qr_buffer.data[8 + (qr_width - 1) * qr_width - (i * qr_width)] = 0xff;
    }
    qr_buffer.data[qr_width * 8 + 9] = 0xff;
    if (version > 5)
    {
        for (int i = 0; i < 6; ++i)
        {
            for (int j = 0; j < 3; ++j)
            {
                qr_buffer.data[(qr_width * (i + 1)) - 11 + j] = 0x00;        // RHS top
                qr_buffer.data[(qr_width * (qr_width - 11 + j)) + i] = 0x00; // LHS bottom
            }
        }
    }

    // Timing Patterns
    for (int i = 8; i < qr_width - 8; ++i)
    {
        int unmasked_offset = qr_width * 6;
        qr_buffer.data[unmasked_offset + i] = (i & 1) * 0xff;
    }
    for (int i = 8; i < qr_width - 8; ++i)
    {
        qr_buffer.data[i * qr_width + 6] = (i & 1) * 0xff;
    }

    // ================================================================
    // Fill
    // ================================================================

    // 8 Mask patterns, if true switch the bit (XOR)
    uint8_t masks[12][12];
    for (int c = 0; c < 12; c++)
    {
        for (int r = 0; r < 12; r++)
        {
            masks[r][c] = 0;
            masks[r][c] |= ((r + c) % 2 == 0) << 0;
            masks[r][c] |= (r % 2 == 0) << 1;
            masks[r][c] |= (c % 3 == 0) << 2;
            masks[r][c] |= ((r + c) % 3 == 0) << 3;
            masks[r][c] |= (((r / 2) + (c / 3)) % 2 == 0) << 4; // Take floor of terms mod 2
            masks[r][c] |= ((r * c) % 2 + (r * c) % 3 == 0) << 5;
            masks[r][c] |= (((r * c) % 2 + (r * c) % 3) % 2 == 0) << 6;
            masks[r][c] |= (((r + c) % 2 + (r * c) % 3) % 2 == 0) << 7;
        }
    }

    interleaved.byte_index = 0;
    interleaved.bit_index = 7;
    int column = qr_width - 1;
    struct limits_t limits = {
        .qr_width = qr_width,
        .row_min = 9,
        .row_max = qr_width - 1,
        .align_col_index = n - 1,
        .align_index_min = 1,
        .align_index_max = n - 1,
        .alignment_positions = alignment_positions};

    fill_up(column, limits, &interleaved, masks, qr_buffer.data);
    column -= 2;
    fill_down(column, limits, &interleaved, masks, qr_buffer.data);
    column -= 2;
    align_up(column, limits, &interleaved, masks, qr_buffer.data);
    column -= 2;
    align_down(column, limits, &interleaved, masks, qr_buffer.data);
    column -= 2;
    limits.row_min = 7;
    align_up(column, limits, &interleaved, masks, qr_buffer.data);
    if (version < 6)
    {
        limits.row_min = 0;
        limits.row_max = 5;
        fill_up(column, limits, &interleaved, masks, qr_buffer.data);
        fill_down(column - 2, limits, &interleaved, masks, qr_buffer.data);
    }
    else // skip version block
    {
        int col = column - 3;
        for (int row = 0; row < 6; ++row)
        {
            int offset = col + row * qr_width;
            qr_buffer.data[offset] = read_bit_stream(&interleaved) ^ masks[row % 12][col % 12];
        }
    }

    --limits.align_col_index;
    limits.row_min = 7;
    limits.row_max = qr_width - 1;
    column -= 2;
    fill_down(column, limits, &interleaved, masks, qr_buffer.data);

    typedef void (*fill_function_t)(const int, const struct limits_t, struct buffer_t *const, const uint8_t[12][12], uint8_t *const);
    fill_function_t regular_fills[2] = {fill_down, fill_up};
    fill_function_t aligned_fills[2] = {align_down, align_up};
    limits.align_index_min = 0;
    limits.row_min = 0;
    column -= 2;
    int fill_direction = 1;
    while (column > 8)
    {
        if (column < alignment_positions[limits.align_col_index] - ALIGNMENT_PATTERN_OFFSET)
        {
            --limits.align_col_index;
        }
        if (column <= alignment_positions[limits.align_col_index] + ALIGNMENT_PATTERN_OFFSET)
        {
            aligned_fills[fill_direction](column, limits, &interleaved, masks, qr_buffer.data);
        }
        else
        {
            regular_fills[fill_direction](column, limits, &interleaved, masks, qr_buffer.data);
        }
        fill_direction ^= 1;
        column -= 2;
    }

    limits.row_max = qr_width - 9;
    limits.row_min = 9;
    limits.align_index_min = 1;
    limits.align_index_max = n - 2;
    align_up(8, limits, &interleaved, masks, qr_buffer.data);
    if (version >= 6)
    {
        limits.row_max -= 3;
    }
    align_down(5, limits, &interleaved, masks, qr_buffer.data);
    fill_up(3, limits, &interleaved, masks, qr_buffer.data);
    fill_down(1, limits, &interleaved, masks, qr_buffer.data);

    // ================================================================
    // Mask Evaluation
    // ================================================================

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
    for (int row = 0; row < qr_width; ++row)
    {
        // Init
        for (int m = 0; m < 8; ++m)
        {
            mask_eval[m].pattern_buffer = 0;
            mask_eval[m].run.last_module = 0;
            mask_eval[m].run.length = 0;
        }
        for (int col = 0; col < qr_width; ++col)
        {
            for (int m = 0; m < 8; ++m)
            {
                int module = (qr_buffer.data[row * qr_width + col] >> m) & 1;
                mask_eval[m].module_count += module;                                                                     // N4
                mask_eval[m].score.pattern += pattern_score(module, &mask_eval[m].pattern_buffer);                       // N3
                mask_eval[m].score.run += repeat_score(module, &mask_eval[m].run.last_module, &mask_eval[m].run.length); // N1
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
    for (int col = 0; col < qr_width; ++col)
    {
        // Init
        uint8_t a = 0xff;
        uint8_t b = ~a;
        for (int m = 0; m < 8; ++m)
        {
            mask_eval[m].pattern_buffer = 0;
            mask_eval[m].run.last_module = 0;
            mask_eval[m].run.length = 0;
        }
        for (int row = 0; row < qr_width; ++row)
        {
            uint8_t c = (0 == col) ? ~a : qr_buffer.data[row * qr_width + col - 1];
            uint8_t d = qr_buffer.data[row * qr_width + col];
            for (int m = 0; m < 8; ++m)
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

    for (int m = 0; m < 8; ++m)
    {
        // N4 final score
        int temp = abs((1000 * mask_eval[m].module_count) / (qr_width * qr_width) - 500) / 50;
        mask_eval[m].score.ratio = temp * 10;
    }

    int mask_score = mask_eval[0].score.block + mask_eval[0].score.pattern + mask_eval[0].score.ratio + mask_eval[0].score.run;
    printf("Mask 0: %d (%d %d %d %d)\n", mask_score, mask_eval[0].score.run, mask_eval[0].score.block, mask_eval[0].score.pattern, mask_eval[0].score.ratio);
    uint8_t mask_pattern_index = 0;
    for (int i = 1; i < 8; ++i)
    {
        int score = mask_eval[i].score.block + mask_eval[i].score.pattern + mask_eval[i].score.ratio + mask_eval[i].score.run;
        printf("Mask %01x: %d (%d %d %d %d)\n", i, score, mask_eval[i].score.run, mask_eval[i].score.block, mask_eval[i].score.pattern, mask_eval[i].score.ratio);
        if (score < mask_score)
        {
            mask_score = score;
            mask_pattern_index = i;
        }
    }
    printf("Mask: %u (%d)\n", mask_pattern_index, mask_score);

    // ================================================================
    // Format
    // ================================================================

    uint16_t format = (uint16_t)(correction_level << 13) | (uint16_t)(mask_pattern_index << 10);
    uint16_t format_generator = BCH_GENERATOR << 4;
    int remainder_bits = 14;
    while (remainder_bits > 9)
    {
        if (1 << remainder_bits & format)
        {
            format ^= format_generator;
        }
        format_generator >>= 1;
        --remainder_bits;
    }
    format |= (uint16_t)(correction_level << 13) | (uint16_t)(mask_pattern_index << 10);

    format ^= QR_FORMAT_MASK; // TODO: uQR support
    printf("Format/Mask: 0x%04x (15 bits)\n", format);

    int function_offset = 8 * qr_width;
    for (int i = 0; i < 6; ++i)
    {
        qr_buffer.data[function_offset + i] = ~(((format >> (14 - i)) & 1) * 0xff);
    }
    qr_buffer.data[function_offset + 7] = ~(((format >> 8) & 1) * 0xff);
    qr_buffer.data[function_offset + 8] = ~(((format >> 7) & 1) * 0xff);
    for (int i = 7; i >= 0; --i)
    {
        qr_buffer.data[function_offset + qr_width - 1 - i] = ~(((format >> i) & 1) * 0xff);
    }

    for (int i = 0; i < 6; ++i)
    {
        qr_buffer.data[i * qr_width + 8] = ~(((format >> i) & 1) * 0xff);
    }
    qr_buffer.data[7 * qr_width + 8] = ~(((format >> 6) & 1) * 0xff);
    qr_buffer.data[(qr_width - 8) * qr_width + 8] = 0;
    for (int i = 7; i > 0; --i)
    {
        qr_buffer.data[(qr_width - i) * qr_width + 8] = ~(((format >> (15 - i)) & 1) * 0xff);
    }

    // ================================================================
    // Version
    // ================================================================

    if (version > 5)
    {
        uint32_t version_code = (uint32_t)((version + 1) << 12);
        uint32_t version_generator = GOLAY_GENERATOR << 5;
        int remainder_bits = 17;
        while (remainder_bits > 11)
        {
            if (1 << remainder_bits & version_code)
            {
                version_code ^= version_generator;
            }
            version_generator >>= 1;
            --remainder_bits;
        }
        version_code |= ((uint32_t)version + 1) << 12;
        printf("Version: 0x%06x (18 bits)\n", version_code);
        for (int i = 0; i < 6; ++i)
        {
            for (int j = 0; j < 3; ++j)
            {
                qr_buffer.data[(qr_width - 11) + i * qr_width + j] = ~(((version_code >> ((i * 3) + j)) & 1) * 0xff);
                qr_buffer.data[qr_width * ((qr_width - 1) - 10 + j) + i] = ~(((version_code >> ((i * 3) + j)) & 1) * 0xff);
            }
        }
    }

    size_t output_struct_size = sizeof(struct qr_data_t);
    size_t output_data_size = (qr_width * qr_width + 0x07) >> 3;
    void *output_buffer = calloc(output_struct_size + output_data_size, sizeof(uint8_t));
    struct qr_data_t *qr_code = (struct qr_data_t *)output_buffer;
    qr_code->err_level = correction_level;
    qr_code->version = version + VERSION_OFFSET;
    qr_code->width = qr_width;
    qr_code->mask = mask_pattern_index;
    qr_code->data = (uint8_t *)(output_buffer + output_struct_size);

    struct buffer_t output_builder = {.bit_index = 0, .byte_index = 0, .data = qr_code->data};
    for (int i = 0; i < qr_width * qr_width; ++i)
    {
        if (output_builder.bit_index > 7)
        {
            output_builder.bit_index = 0;
            ++output_builder.byte_index;
        }
        output_builder.data[output_builder.byte_index] |= ((qr_buffer.data[i] >> mask_pattern_index) & 1) << (7 - output_builder.bit_index);
        ++output_builder.bit_index;
    }

    free(qr_buffer.data);
    free(interleaved.data);
    free(encoded.data);
    qr_buffer.data = NULL;
    interleaved.data = NULL;
    encoded.data = NULL;
    return qr_code;
}

int main(int argc, char **argv)
{
    struct user_params_t params;
    if (EXIT_FAILURE == parse_qr_input(argc, (const char const *const *)argv, &params))
    {
        return EXIT_FAILURE;
    }

    struct qr_data_t *qr_code = qr_encode(params.version, params.correction_level, argv[argc - 1]);
    if (qr_code != NULL)
    {
        export_as_ppm(qr_code->width, qr_code->data);
    }

    free(qr_code);
    qr_code = NULL;
}
