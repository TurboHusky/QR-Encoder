#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qr.h"

#ifdef DEBUG
char correction_map[] = {'M', 'L', 'H', 'Q', 'A'};
#define PRINT_DBG(...) printf(__VA_ARGS__)
#else
#define PRINT_DBG(...) //
#endif

#define EVAL_BUFFER_SIZE 64

#define VERSION_OFFSET 1
#define VERSION_MIN 1
#define VERSION_MODULE_TOTAL 36
#define BUILD_VERSION_INFO 6
#define GF256_ANTILOG 0
#define GF256_LOG 1

#define ERR_WORDS_PER_BLOCK 0
#define GROUP_1_BLOCK_COUNT 1
#define GROUP_1_BLOCK_SIZE 2
#define GROUP_2_BLOCK_COUNT 3
#define GROUP_2_BLOCK_SIZE 4

#define QR_TYPE_INDICATOR_SIZE 4

#define ALIGNMENT_POSITIONS_MAX 7
#define ALIGNMENT_PATTERN_OFFSET 2
#define ALIGNMENT_PATTERN_WIDTH 5
#define TIMING_PATTERN_OFFSET 6

#define EVAL_PATTERN_MASK 0x07ffu
#define EVAL_PATTERN_LEFT 0x07a2u
#define EVAL_PATTERN_RIGHT 0x022fu

#define QR_FORMAT_MASK 0x5412u
#define MICRO_QR_FORMAT_MASK 0X4445u
#define BCH_GENERATOR 0x0537u
#define GOLAY_GENERATOR 0x1f25u

#define ENCODING_TYPE_COUNT 4

#define BITS_PER_KANJI_CHAR 13
#define BITS_PER_THREE_NUMERIC_CHARS 10
#define BITS_PER_TWO_ALPHANUMERIC_CHARS 11
#define BITS_PER_SINGLE_ALPHANUMERIC_CHAR 6

#define BYTE_MASK 0x04U
#define KANJI_MASK 0x08U
#define ALPHANUMERIC_MASK 0x02U
#define NUMERIC_MASK 0x01U

enum char_encoding_t
{
    NUMERIC_DATA = 0,
    ALPHANUMERIC_DATA = 1,
    BYTE_DATA = 2,
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

struct buffer_t
{
    uint8_t *data;
    size_t size;
    size_t byte_index;
    uint8_t bit_index;
};

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

const uint8_t char_encoding_masks[ENCODING_TYPE_COUNT] = {NUMERIC_MASK, ALPHANUMERIC_MASK, BYTE_MASK, KANJI_MASK};

// order matches char_encoding_t
const int header_sizes[7][ENCODING_TYPE_COUNT] = {
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

static inline void add_to_buffer(uint16_t data, int bitcount, struct buffer_t *const buffer)
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

static inline uint8_t read_bit_stream(struct buffer_t *const buffer)
{
    uint8_t result = (buffer->data[buffer->byte_index] >> buffer->bit_index) & 1;
    --buffer->bit_index;
    buffer->bit_index &= 0x07u;
    buffer->byte_index += (size_t)((buffer->bit_index + 1) >> 3);
    return (uint8_t)(~(result * 0xffu));
}

// void qr_free(struct qr_data_t *qr_code)
// {
//     free(qr_code->data);
//     qr_code->data = NULL;
// }

// output:  10 bits for 3 digits
//           7 bits for 2
//           4 bits for 1
static inline void encode_numeric(const struct buffer_t input, struct buffer_t *const output)
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
        add_to_buffer((uint16_t)((input.data[index] - '0') * 10 + input.data[index + 1] - '0'), 7, output);
        break;
    case 1:
        add_to_buffer(input.data[index] - '0', 4, output);
        break;
    default:
        break;
    }
}

// output:  11 bits per pair
//           6 bits for a single character
static inline void encode_alphanumeric(const struct buffer_t input, struct buffer_t *const output)
{
    const char alphanumeric_lookup[59] = {
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

// output:  13 bits per 2-byte character
static inline void encode_kanji(const struct buffer_t input, struct buffer_t *const output)
{
    for (size_t i = 0; i < input.size; i += 2)
    {
        uint16_t hi = (uint16_t)(input.data[i] << 8);
        uint16_t lo = (uint16_t)input.data[i + 1];
        uint16_t temp = hi | lo;
        if (temp <= 0x9FFC)
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

static inline void encode_byte(const struct buffer_t input, struct buffer_t *const output)
{
    for (size_t i = 0; i < input.size; ++i)
    {
        add_to_buffer(input.data[i], 8, output);
    }
}

static inline enum char_encoding_t input_type(const char c1, const char c2)
{
    uint8_t byte1 = (uint8_t)c1;
    uint8_t byte2 = (uint8_t)c2;

    if (byte1 >= '0' && byte1 <= '9')
    {
        return NUMERIC_DATA;
    }
    if ((byte1 >= 'A' && byte1 <= 'Z') || ' ' == byte1 || '$' == byte1 || '%' == byte1 || '*' == byte1 || '+' == byte1 || '-' == byte1 || '.' == byte1 || '/' == byte1 || ':' == byte1)
    {
        return ALPHANUMERIC_DATA;
    }
    if (((byte1 >= 0x81) && (byte1 <= 0x9F)) || ((byte1 >= 0xE0) && (byte1 <= 0xEA)))
    {
        if ((byte2 >= 0x40) && (byte2 <= 0xFC) && (byte2 != 0x7F))
        {
            return KANJI_DATA;
        }
    }
    if (byte1 == 0xEB)
    {
        if ((byte2 >= 0x40) && (byte2 <= 0xBF) && (byte2 != 0x7F))
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
    case NUMERIC_DATA:
    {
        size_t remainder_bits[] = {0, 4, 7};
        return (char_count / 3) * BITS_PER_THREE_NUMERIC_CHARS + remainder_bits[char_count % 3];
    }
    case BYTE_DATA:
        return char_count << 3;
    case KANJI_DATA:
        return (char_count >> 1) * BITS_PER_KANJI_CHAR;
    case ALPHANUMERIC_DATA:
        return (char_count >> 1) * BITS_PER_TWO_ALPHANUMERIC_CHARS + ((char_count & 0x01U) ? BITS_PER_SINGLE_ALPHANUMERIC_CHAR : 0);
    }
    return 0; // Should never happen
}

struct encoding_run_t
{
    enum char_encoding_t type;
    size_t char_count;
};

size_t merge_data(const int header_bit_count[ENCODING_TYPE_COUNT], const int masks, const enum char_encoding_t merge_target, struct encoding_run_t *const list, const size_t list_size)
{
    if (list_size < 2)
    {
        return list_size;
    }
    size_t index = 0;
    size_t end = 1;
    while (end < list_size)
    {
        if ((0 != (char_encoding_masks[list[index].type] & masks)) && (list[end].type == merge_target))
        {
            const size_t cost = encoding_size(merge_target, list[index].char_count);
            size_t new_cost = (size_t)header_bit_count[list[index].type] + encoding_size(list[index].type, list[index].char_count);
            if (new_cost >= cost)
            {
                list[index].type = list[end].type;
                list[index].char_count += list[end].char_count;
                ++end;
                continue;
            }
        }
        else if ((0 != (char_encoding_masks[list[end].type] & masks)) && (list[index].type == merge_target))
        {
            const size_t cost = encoding_size(merge_target, list[end].char_count);
            size_t new_cost = (size_t)header_bit_count[list[end].type] + encoding_size(list[end].type, list[end].char_count);
            if (list[end + 1].type == merge_target)
            {
                new_cost += (size_t)header_bit_count[merge_target];
                if (new_cost >= cost)
                {
                    list[index].char_count += list[end].char_count + list[end + 1].char_count;
                    end += 2;
                    continue;
                }
            }
            else if (new_cost >= cost)
            {
                list[index].char_count += list[end].char_count;
                ++end;
                continue;
            }
        }
        ++index;
        struct encoding_run_t temp = list[end];
        list[index] = temp;
        ++end;
    }
    ++index;
    list[index].char_count = 0;
    return index;
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
        uint8_t multiplier = gf256_lookup[error_words[0]][GF256_LOG]; // Generator multiplication factor
        for (size_t k = 1; k < (size_t)error_word_count; ++k)
        {
            // Multiply generator by leading term in data polynomial (add antilogs mod 255)
            temp = (uint8_t)((multiplier + gf256_lookup[generator[(unsigned int)generator_start + k]][GF256_LOG]) % 255);
            // Add generator to data polynomial (XOR to cancel leading term)
            error_words[k - 1] = gf256_lookup[temp][GF256_ANTILOG] ^ error_words[k];
        }
        temp = (uint8_t)((multiplier + gf256_lookup[generator[generator_end]][GF256_LOG]) % 255);
        if (j + error_word_count < data_word_count)
        {
            error_words[error_word_count - 1] = gf256_lookup[temp][GF256_ANTILOG] ^ input[j + error_word_count];
        }
        else
        {
            error_words[error_word_count - 1] = gf256_lookup[temp][GF256_ANTILOG];
        }
    }
    for (int k = 0; k < error_word_count; ++k)
    {
        PRINT_DBG("%02x ", error_words[k]);
    }
    PRINT_DBG("\n");
}

// See Table 1 of ISO-IEC-18004
int compute_alignment_positions(const int version, int *const coords) // version 1-40
{
    if (version <= VERSION_MIN)
    {
        return 0;
    }
    int intervals = (version / 7) + 1; // Number of gaps between alignment patterns
    int distance = 4 * version + 4;    // Distance between first and last alignment pattern
    int step = distance / intervals;
    if ((distance % intervals << 1) >= intervals) // Round spacing to nearest integer
    {
        ++step;
    }
    step += step & 1; // Round step to next even number
    coords[0] = 6;    // First coordinate is always 6 (can't be calculated with step)
    for (int i = 1; i <= intervals; ++i)
    {
        coords[i] = 6 + distance - step * (intervals - i); // Start right/bottom and go left/up by step*k
    }
    return intervals + 1;
}

int qr_size(const int version, const int alignment_pattern_count)
{
    const int version_1 = version + VERSION_OFFSET; // version 1-40
    int N = 17 + version_1 * 4;                     // QR width
    int free_modules = N * (N - 2) - 191;           // ((N - 17) x 8) x 2 + (N - 9)^2
    if (version_1 > 1)
    {
        free_modules -= alignment_pattern_count * (alignment_pattern_count * 25 - 10) - 55; // (M - 2) x 20 x 2 + (M - 1)^2 x 25
    }
    if (version_1 > 6)
    {
        free_modules -= VERSION_MODULE_TOTAL;
    }
    return free_modules;
}

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

// Build list of run/length values for input types. List must terminate with a "null" entry (char_count = 0)
uint8_t parse_input(const char *const input, struct encoding_run_t **list_ptr, size_t *const list_capacity, size_t *const list_size)
{
    struct encoding_run_t *encoding_list = *list_ptr;
    uint8_t data_types = 0;
    size_t run = 0;
    size_t char_count = 0;
    enum char_encoding_t type = input_type(input[char_count], input[char_count + 1]);
    while (input[char_count] != '\0')
    {
        enum char_encoding_t new_type = input_type(input[char_count], input[char_count + 1]);
        data_types |= char_encoding_masks[new_type];
        if (new_type == type)
        {
            ++run;
        }
        else
        {
            if (*list_size >= *list_capacity - 2)
            {
                *list_capacity <<= 1;
                *list_ptr = (struct encoding_run_t *)realloc(*list_ptr, *list_capacity * sizeof(struct encoding_run_t));
                encoding_list = *list_ptr;
                if (NULL == encoding_list)
                {
                    PRINT_DBG("Failed to increase buffer list size\n");
                    return 0;
                }
            }
            encoding_list[*list_size].type = type;
            encoding_list[*list_size].char_count = run;
            ++(*list_size);

            type = new_type;
            run = 1;
        }
        if (KANJI_DATA == type)
        {
            ++char_count;
            if (input[char_count] == '\0')
            {
                break;
            }
        }
        ++char_count;
    }
    encoding_list[*list_size].type = type;
    encoding_list[*list_size].char_count = run;
    ++(*list_size);
    encoding_list[*list_size].type = type;
    encoding_list[*list_size].char_count = 0;

    return data_types;
}

int min_micro_qr_version(const uint8_t data_types, const enum error_correction_level_t correction_level)
{
    if (CORRECTION_LEVEL_AUTO == correction_level)
    {
        if (0 == (data_types & ~NUMERIC_MASK))
        {
            return 0;
        }
        if (0 == (data_types & ~(NUMERIC_MASK | ALPHANUMERIC_MASK)))
        {
            return 1;
        }
        return 2;
    }
    if ((CORRECTION_LEVEL_L == correction_level) || (CORRECTION_LEVEL_M == correction_level))
    {
        if (0 == (data_types & ~(NUMERIC_MASK | ALPHANUMERIC_MASK)))
        {
            return 1;
        }
        else
        {
            return 2;
        }
    }
    if (CORRECTION_LEVEL_H != correction_level)
    {
        return 3;
    }
    return 4;
}

int optimise_input(const int micro_version, const enum error_correction_level_t correction_level, struct encoding_run_t *const encoding_list, size_t *const list_size, int *const module_count)
{
    int header_index = micro_version;
    // M1, M2, M3, M4, 1-9, 10-26, 27-40
    int module_limits[7] = {
        micro_module_capacities[0][CORRECTION_LEVEL_L],
        micro_module_capacities[1][correction_level],
        micro_module_capacities[2][correction_level],
        micro_module_capacities[3][correction_level],
        (error_blocks[8][correction_level][1] * error_blocks[8][correction_level][2] + error_blocks[8][correction_level][3] * error_blocks[8][correction_level][4]) << 3,
        (error_blocks[25][correction_level][1] * error_blocks[25][correction_level][2] + error_blocks[25][correction_level][3] * error_blocks[25][correction_level][4]) << 3,
        (error_blocks[39][correction_level][1] * error_blocks[39][correction_level][2] + error_blocks[39][correction_level][3] * error_blocks[39][correction_level][4]) << 3};
    while (header_index < 7)
    {
        *list_size = merge_data(header_sizes[header_index], NUMERIC_MASK, ALPHANUMERIC_DATA, encoding_list, *list_size);
        *list_size = merge_data(header_sizes[header_index], NUMERIC_MASK | ALPHANUMERIC_MASK | KANJI_MASK, BYTE_DATA, encoding_list, *list_size);

        *module_count = 0;
        for (size_t j = 0; j < *list_size; ++j)
        {
            if (encoding_list[j].char_count > 0)
            {
                *module_count += header_sizes[header_index][encoding_list[j].type];
                *module_count += (int)encoding_size(encoding_list[j].type, encoding_list[j].char_count);
            }
        }
        if (*module_count <= module_limits[header_index])
        {
            break;
        }
        ++header_index;
    }
    return header_index;
}

enum code_type_t compute_data_word_sizes(const enum error_correction_level_t correction_level, const int module_count, const int header_index, int *const version, size_t *const data_word_total, size_t *const error_word_total)
{
    enum code_type_t qr_type = QR_SIZE_STANDARD;
    if (header_index < 4)
    {
        qr_type = QR_SIZE_MICRO;
        *version = header_index;
        *data_word_total = (size_t)(((micro_module_capacities[*version][correction_level] + 4) >> 3));
        *error_word_total = (size_t)micro_error_words[*version][correction_level];
    }
    else
    {
        const int *block_data;
        int max_versions[] = {8, 25, 39};
        *version = max_versions[header_index - 4];
        while (*version > 0)
        {
            block_data = error_blocks[*version - 1][correction_level];
            int capacity = (block_data[GROUP_1_BLOCK_COUNT] * block_data[GROUP_1_BLOCK_SIZE] + block_data[GROUP_2_BLOCK_COUNT] * block_data[GROUP_2_BLOCK_SIZE]) << 3;
            if (module_count > capacity)
            {
                break;
            }
            --(*version);
        }
        block_data = error_blocks[*version][correction_level];
        *data_word_total = (size_t)(block_data[GROUP_1_BLOCK_COUNT] * block_data[GROUP_1_BLOCK_SIZE] + block_data[GROUP_2_BLOCK_COUNT] * block_data[GROUP_2_BLOCK_SIZE]);
        *error_word_total = (size_t)(block_data[ERR_WORDS_PER_BLOCK] * (block_data[GROUP_1_BLOCK_COUNT] + block_data[GROUP_2_BLOCK_COUNT]));
    }

    return qr_type;
}

void qr_encode_input(const enum code_type_t qr_type, const int version, const enum error_correction_level_t correction_level, const int module_count, const char *const buffer, const struct encoding_run_t *const final_list, const size_t list_size, struct buffer_t *const encoder_buffer)
{
    typedef void (*encoder_t)(const struct buffer_t, struct buffer_t *const);
    encoder_t encoders[ENCODING_TYPE_COUNT] = {encode_numeric, encode_alphanumeric, encode_byte, encode_kanji};
    size_t offset = 0;
    for (size_t i = 0; i < list_size; ++i)
    {
        if (final_list[i].char_count > 0)
        {
            if (QR_SIZE_MICRO == qr_type)
            {
                uint16_t count_indicator_lengths[4][ENCODING_TYPE_COUNT] = {{3, 0, 0, 0}, {4, 3, 0, 0}, {5, 4, 4, 3}, {6, 5, 5, 4}}; // Char count indicators
                add_to_buffer((uint16_t)final_list[i].type, version, encoder_buffer);                              // Mode indicator (N/A for M1)
                add_to_buffer((uint16_t)final_list[i].char_count, count_indicator_lengths[version][final_list[i].type], encoder_buffer);
            }
            else
            {
                int count_indicator_lengths[ENCODING_TYPE_COUNT] = {10, 9, 8, 8};
                int bitcount = count_indicator_lengths[final_list[i].type];
                if (version >= 9)
                {
                    bitcount += 2;
                }
                if (version >= 26)
                {
                    bitcount += 2;
                }
                if ((BYTE_DATA == final_list[i].type) && (bitcount > 8))
                {
                    bitcount = 16;
                }
                add_to_buffer((uint16_t)(1 << final_list[i].type), QR_TYPE_INDICATOR_SIZE, encoder_buffer);
                add_to_buffer((uint16_t)final_list[i].char_count, bitcount, encoder_buffer);
            }

            struct buffer_t temp = {.bit_index = 0, .byte_index = 0, .size = final_list[i].char_count};
            temp.data = (uint8_t *)(buffer + offset);
            encoders[final_list[i].type](temp, encoder_buffer);
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
    PRINT_DBG("Encoded len check: %d %lu, QR capacity: %d, %d bits unused\n", module_count, (encoder_buffer->byte_index << 3) + (size_t)encoder_buffer->bit_index, qr_capacity, qr_capacity - module_count);

    // Terminators
    int terminator_length = (QR_SIZE_MICRO == qr_type) ? ((version + 1) << 1) + 1 : 4;
    if ((qr_capacity - module_count) > terminator_length)
    {
        add_to_buffer(0, terminator_length, encoder_buffer);
    }
    // Padding
    encoder_buffer->byte_index += (size_t)((encoder_buffer->bit_index + 0x07) >> 3);
    encoder_buffer->bit_index = 0;
    uint8_t pad_byte = 0xEC;
    while (encoder_buffer->byte_index < (size_t)(qr_capacity >> 3))
    {
        encoder_buffer->data[encoder_buffer->byte_index] = pad_byte;
        ++encoder_buffer->byte_index;
        pad_byte ^= 0xFD;
    }
}

void GenerateGF256Lookup(uint8_t gf256_lookup[256][2])
{
    uint16_t gf256_base = 1;
    gf256_lookup[0][GF256_LOG] = 0; // No exponent exists for zero value coefficient
    for (int i = 0; i < 256; ++i)
    {
        gf256_lookup[i][GF256_ANTILOG] = (uint8_t)gf256_base;
        gf256_lookup[gf256_base][GF256_LOG] = (uint8_t)i;
        gf256_base <<= 1;
        if (gf256_base > 255)
        {
            gf256_base ^= 285;
        }
    }
    gf256_lookup[1][GF256_LOG] = 0;
    gf256_lookup[255][GF256_ANTILOG] = 0;
    // for (int i = 0; i< 256; ++i) {PRINT_DBG(" %u %u\n", gf256_lookup[i][0], gf256_lookup[i][1]);}PRINT_DBG("\n");
}

void GenerateErrorPolynomial(const int target_exponent, uint8_t gf256_lookup[256][2], uint8_t *const gen8)
{
    gen8[target_exponent] = 2;
    gen8[target_exponent - 1] = 3;
    gen8[target_exponent - 2] = 1;
    for (int gen_exp = 3; gen_exp <= target_exponent; ++gen_exp)
    {
        uint8_t last_generator_value = 0;
        for (int i = 0; i < gen_exp; ++i)
        {
            uint8_t temp = (gf256_lookup[(gf256_lookup[gen8[target_exponent - i]][GF256_LOG] + gen_exp - 1) % 255][GF256_ANTILOG]) ^ last_generator_value;
            last_generator_value = gen8[target_exponent - i];
            gen8[target_exponent - i] = temp;
        }
        gen8[target_exponent - gen_exp] = 1;
    }
}

void qr_error_correction(const enum code_type_t qr_type, const int version, const enum error_correction_level_t correction_level, const int block_data[5], struct buffer_t *const encoder_buffer, const size_t data_word_total)
{
    uint8_t gf256_lookup[256][2];
    GenerateGF256Lookup(gf256_lookup);

    int generator_exponent = 2;
    // ERR: Too short for larger polynomials, QR standard can reach 69 terms
    uint8_t generator[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 2};
    int generator_end = sizeof(generator) - 1;
    int target_exponent = (QR_SIZE_MICRO == qr_type) ? micro_error_words[version][correction_level] : error_blocks[version][correction_level][ERR_WORDS_PER_BLOCK];
    // TODO: Simplify polynomial generator to bytes + length
    GenerateErrorPolynomial(target_exponent, gf256_lookup, generator + (generator_end - target_exponent));
    generator_exponent = target_exponent;
    // int generator_size = generator_exponent + 1;
    int generator_start = (int)(sizeof(generator) - (size_t)generator_exponent - 1);

    PRINT_DBG("Generator exponent: %d (%d terms)\n", generator_exponent, generator_exponent + 1);
    for (int i = 0; i <= generator_exponent; ++i)
    {
        PRINT_DBG("%d ", generator[generator_end - generator_exponent + i]);
    }
    PRINT_DBG("\n");

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

    PRINT_DBG("Error codes:\n");

    {
        size_t block_offset = 0;
        size_t err_offset = 0;
        for (int i = 0; i < block_data[GROUP_1_BLOCK_COUNT]; ++i)
        {
            PRINT_DBG("Group 1, Block %d ", i + 1);
            calculate_error_codes(block_data[GROUP_1_BLOCK_SIZE], block_data[ERR_WORDS_PER_BLOCK], (const uint8_t (*const)[2])gf256_lookup, generator_start, generator_end, generator, encoder_buffer->data + block_offset, encoder_buffer->data + data_word_total + err_offset);
            block_offset += (size_t)block_data[GROUP_1_BLOCK_SIZE];
            err_offset += (size_t)block_data[ERR_WORDS_PER_BLOCK];
        }
        for (int i = 0; i < block_data[GROUP_2_BLOCK_COUNT]; ++i)
        {
            PRINT_DBG("Group 2, Block %d ", i + 1);
            calculate_error_codes(block_data[GROUP_2_BLOCK_SIZE], block_data[ERR_WORDS_PER_BLOCK], (const uint8_t (*const)[2])gf256_lookup, generator_start, generator_end, generator, encoder_buffer->data + block_offset, encoder_buffer->data + data_word_total + err_offset);
            block_offset += (size_t)block_data[GROUP_2_BLOCK_SIZE];
            err_offset += (size_t)block_data[ERR_WORDS_PER_BLOCK];
        }
    }
}

void qr_interleave(const int block_data[5], const size_t data_word_total, const struct buffer_t *const encoder_buffer, uint8_t *const interleaved_data)
{
    // Interleave data words
    int line_index = 0;
    size_t interleaved_index = 0;
    while (line_index < block_data[GROUP_1_BLOCK_SIZE] || line_index < block_data[GROUP_2_BLOCK_SIZE])
    {
        if (line_index < block_data[GROUP_1_BLOCK_SIZE])
        {
            for (int i = 0; i < block_data[GROUP_1_BLOCK_COUNT]; ++i)
            {
                interleaved_data[interleaved_index] = encoder_buffer->data[i * block_data[GROUP_1_BLOCK_SIZE] + line_index];
                ++interleaved_index;
            }
        }
        if (line_index < block_data[GROUP_2_BLOCK_SIZE])
        {
            for (int i = 0; i < block_data[GROUP_2_BLOCK_COUNT]; ++i)
            {
                interleaved_data[interleaved_index] = encoder_buffer->data[(block_data[GROUP_1_BLOCK_COUNT] * block_data[GROUP_1_BLOCK_SIZE]) + i * block_data[GROUP_2_BLOCK_SIZE] + line_index];
                ++interleaved_index;
            }
        }
        ++line_index;
    }

    // Interleave error words
    int num_error_code_blocks = block_data[GROUP_1_BLOCK_COUNT] + block_data[GROUP_2_BLOCK_COUNT];
    for (size_t i = 0; i < (size_t)block_data[ERR_WORDS_PER_BLOCK]; ++i)
    {
        for (size_t j = 0; j < (size_t)num_error_code_blocks; ++j)
        {
            interleaved_data[interleaved_index] = encoder_buffer->data[data_word_total + i + j * (size_t)block_data[ERR_WORDS_PER_BLOCK]];
            ++interleaved_index;
        }
    }
}

void qr_setup(const enum code_type_t qr_type, const size_t qr_width, const int n, const int *const alignment_positions, struct buffer_t *const qr_buffer)
{
    // Alignment Patterns
    if (QR_SIZE_STANDARD == qr_type)
    {
        const uint8_t alignment_pattern[ALIGNMENT_PATTERN_WIDTH] = {0xe0u, 0xeeu, 0xeau, 0xeeu, 0xe0u};
        for (int grid_x = 0; grid_x < n; ++grid_x)
        {
            for (int grid_y = 0; grid_y < n; ++grid_y)
            {
                if ((0 == grid_x && (0 == grid_y || ((n - 1) == grid_y))) || ((n - 1) == grid_x && 0 == grid_y))
                {
                    continue;
                }
                size_t alignment_offset = qr_width * (size_t)(alignment_positions[grid_y] - 2) + (size_t)alignment_positions[grid_x] - 2;
                for (int row = 0; row < ALIGNMENT_PATTERN_WIDTH; ++row)
                {
                    for (size_t col = 0; col < ALIGNMENT_PATTERN_WIDTH; ++col)
                    {
                        qr_buffer->data[alignment_offset + col] = ((alignment_pattern[row] >> col) & 1) * 0xffu;
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
            qr_buffer->data[finder_index + col] = ((finder_pattern[row] >> col) & 1) * 0xffu;
        }
    }

    if (QR_SIZE_STANDARD == qr_type)
    {
        for (size_t row = 0; row < 8; ++row)
        {
            qr_buffer->data[qr_width * (row + 1) - 8] = 0xffu;
            memcpy(qr_buffer->data + qr_width * (row + 1) - 7, qr_buffer->data + qr_width * row, 7);
        }
        memcpy(qr_buffer->data + qr_width * (qr_width - 8), qr_buffer->data + qr_width * 7, 8);
        for (size_t row = 0; row < 7; ++row)
        {
            memcpy(qr_buffer->data + qr_width * (qr_width - 7 + row), qr_buffer->data + qr_width * row, 8);
        }
    }

    // Timing Patterns
    if (QR_SIZE_MICRO == qr_type)
    {
        for (size_t i = 8; i < qr_width; ++i)
        {
            uint8_t val = (i & 1) * 0xffu;
            qr_buffer->data[i] = val;
            qr_buffer->data[i * qr_width] = val;
        }
    }
    if (QR_SIZE_STANDARD == qr_type)
    {
        size_t row_offset = qr_width * TIMING_PATTERN_OFFSET;
        for (size_t i = 8; i < qr_width - 8; ++i)
        {
            uint8_t val = (i & 1) * 0xffu;
            qr_buffer->data[row_offset + i] = val;
            qr_buffer->data[i * qr_width + TIMING_PATTERN_OFFSET] = val;
        }
    }
}

void qr_fill(const enum code_type_t qr_type, const int version, const size_t qr_width, uint8_t *const interleaved_data, size_t qr_data_size, const int *const alignment_positions, const int n, struct buffer_t *const qr_buffer)
{
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

    struct buffer_t interleaved_buffer = {.byte_index = 0, .bit_index = 7, .data = interleaved_data, .size = qr_data_size};

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
            fill[dir](&interleaved_buffer, col, 1, (int)qr_width - 1, -1, -1, &fill_settings, qr_buffer->data);
            dir ^= 1;
            col -= 2;
        }
        while (col > 0)
        {
            fill[dir](&interleaved_buffer, col, 9, (int)qr_width - 1, -1, -1, &fill_settings, qr_buffer->data);
            dir ^= 1;
            col -= 2;
        }
    }
    else
    {
        fill_settings.alignment.positions = alignment_positions,
        fill_settings.alignment.size = n;
        fill_u(&interleaved_buffer, (int)qr_width - 1, 9, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer->data);
        fill_d(&interleaved_buffer, (int)qr_width - 3, 9, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer->data);
        fill_u(&interleaved_buffer, (int)qr_width - 5, 9, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer->data);
        fill_d(&interleaved_buffer, (int)qr_width - 7, 9, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer->data);

        fill_u(&interleaved_buffer, (int)qr_width - 9, 7, (int)qr_width - 1, 1, n - 1, &fill_settings, qr_buffer->data);
        if (version < BUILD_VERSION_INFO)
        {
            fill_u(&interleaved_buffer, (int)qr_width - 9, 0, 5, 1, 1, &fill_settings, qr_buffer->data);
            fill_d(&interleaved_buffer, (int)qr_width - 11, 0, 5, 1, 1, &fill_settings, qr_buffer->data);
        }
        else
        {
            for (int i = 0; i < 6; ++i)
            {
                qr_buffer->data[(int)qr_width * i + (int)qr_width - 12] = read_bit_stream(&interleaved_buffer) ^ fill_settings.masks[i % 12][(qr_width - 12) % 12];
            }
        }
        fill_d(&interleaved_buffer, (int)qr_width - 11, 7, (int)qr_width - 1, 0, n - 1, &fill_settings, qr_buffer->data);

        for (int i = (int)qr_width - 13; i > 8; i -= 2)
        {
            if (0 == ((i >> 1) & 1))
            {
                fill_u(&interleaved_buffer, i, 7, (int)qr_width - 1, 0, n - 1, &fill_settings, qr_buffer->data);
                fill_u(&interleaved_buffer, i, 0, 5, 0, 0, &fill_settings, qr_buffer->data);
            }
            else
            {
                fill_d(&interleaved_buffer, i, 0, 5, 0, 0, &fill_settings, qr_buffer->data);
                fill_d(&interleaved_buffer, i, 7, (int)qr_width - 1, 0, n - 1, &fill_settings, qr_buffer->data);
            }
        }
        fill_u(&interleaved_buffer, 8, 9, (int)qr_width - 9, 1, n - 2, &fill_settings, qr_buffer->data);
        int version_offset = (version < BUILD_VERSION_INFO) ? 9 : 12;
        fill_d(&interleaved_buffer, 5, 9, (int)qr_width - version_offset, 1, n - 2, &fill_settings, qr_buffer->data);
        fill_u(&interleaved_buffer, 3, 9, (int)qr_width - version_offset, 1, n - 2, &fill_settings, qr_buffer->data);
        PRINT_DBG("[%lu:%u] of %lu - %lu bits remaining in buffer, %lu required to fill\n", interleaved_buffer.byte_index, interleaved_buffer.bit_index, interleaved_buffer.size, ((interleaved_buffer.size - interleaved_buffer.byte_index - 1) << 3) + interleaved_buffer.bit_index + 1, (qr_width - (size_t)version_offset - 8) << 1);
        fill_d(&interleaved_buffer, 1, 9, (int)qr_width - version_offset, 1, n - 2, &fill_settings, qr_buffer->data);
    }
}

uint8_t evaluate_masks(const enum code_type_t qr_type, const size_t qr_width, const struct buffer_t *const qr_buffer)
{
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
                sum1 += (qr_buffer->data[(i + 1) * qr_width - 1] & mask) == 0;
                sum2 += (qr_buffer->data[qr_width * qr_width - i] & mask) == 0;
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
                    size_t module = (qr_buffer->data[row * qr_width + col] >> m) & 1;
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
                uint8_t c = (0 == col) ? ~a : qr_buffer->data[row * qr_width + col - 1];
                uint8_t d = qr_buffer->data[row * qr_width + col];
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
        PRINT_DBG("Mask 0: %d (%d %d %d %d)\n", mask_score, mask_eval[0].score.run, mask_eval[0].score.block, mask_eval[0].score.pattern, mask_eval[0].score.ratio);
        mask_pattern_index = 0;
        for (int i = 1; i < 8; ++i)
        {
            int score = mask_eval[i].score.block + mask_eval[i].score.pattern + mask_eval[i].score.ratio + mask_eval[i].score.run;
            PRINT_DBG("Mask %01x: %d (%d %d %d %d)\n", i, score, mask_eval[i].score.run, mask_eval[i].score.block, mask_eval[i].score.pattern, mask_eval[i].score.ratio);
            if (score < mask_score)
            {
                mask_score = score;
                mask_pattern_index = (uint8_t)i;
            }
        }
    }
    PRINT_DBG("Mask: %u (%d)\n", mask_pattern_index, mask_score);
    return mask_pattern_index;
}

void qr_add_format(const enum code_type_t qr_type, const int version, const enum error_correction_level_t correction_level, const uint8_t mask_pattern_index, const size_t qr_width, struct buffer_t *const qr_buffer)
{
    uint16_t format_data;
    if (QR_SIZE_MICRO == qr_type)
    {
        uint16_t binary_indicators[] = {0, 1, 3, 5};
        format_data = binary_indicators[version];
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
    PRINT_DBG("Format/Mask: 0x%04x (15 bits)\n", format);
    if (QR_SIZE_MICRO == qr_type)
    {
        size_t function_offset = qr_width + 8;
        for (size_t i = 0; i < 7; ++i)
        {
            qr_buffer->data[function_offset] = (uint8_t)~(((format >> i) & 1) * 0xffu);
            function_offset += qr_width;
        }
        for (size_t i = 7; i < 15; ++i)
        {
            qr_buffer->data[function_offset] = (uint8_t)~(((format >> i) & 1) * 0xffu);
            --function_offset;
        }
    }
    else
    {
        size_t function_offset = 8 * qr_width;
        for (size_t i = 0; i < 6; ++i)
        {
            qr_buffer->data[function_offset + i] = (uint8_t)~(((format >> (14 - i)) & 1) * 0xffu);
        }
        qr_buffer->data[function_offset + 7] = (uint8_t)~(((format >> 8) & 1) * 0xffu);
        qr_buffer->data[function_offset + 8] = (uint8_t)~(((format >> 7) & 1) * 0xffu);
        for (int i = 7; i >= 0; --i)
        {
            qr_buffer->data[function_offset + qr_width - 1 - (size_t)i] = (uint8_t)~(((format >> i) & 1) * 0xffu);
        }

        for (size_t i = 0; i < 6; ++i)
        {
            qr_buffer->data[i * qr_width + 8] = (uint8_t)~(((format >> i) & 1) * 0xffu);
        }
        qr_buffer->data[7 * qr_width + 8] = (uint8_t)~(((format >> 6) & 1) * 0xffu);
        qr_buffer->data[(qr_width - 8) * qr_width + 8] = 0;
        for (size_t i = 7; i > 0; --i)
        {
            qr_buffer->data[(qr_width - i) * qr_width + 8] = (uint8_t)~(((format >> (15 - i)) & 1) * 0xffu);
        }
    }
}

void qr_add_version(const int version, const size_t qr_width, struct buffer_t *const qr_buffer)
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
    PRINT_DBG("Version: 0x%06x (18 bits)\n", version_code);
    for (size_t i = 0; i < 6; ++i)
    {
        for (size_t j = 0; j < 3; ++j)
        {
            qr_buffer->data[(qr_width - 11) + i * qr_width + j] = (uint8_t)~(((version_code >> ((i * 3) + j)) & 1) * 0xffu);
            qr_buffer->data[qr_width * ((qr_width - 1) - 10 + j) + i] = (uint8_t)~(((version_code >> ((i * 3) + j)) & 1) * 0xffu);
        }
    }
}

enum encoding_status_t qr_encode(enum code_type_t qr_code_type, const enum error_correction_level_t qr_correction_level, const int qr_version, const char *const input_data, struct qr_data_t **qr_code)
{
    if (input_data[0] == '\0')
    {
        PRINT_DBG("Empty input\n");
        return QR_ENC_NO_INPUT_DATA;
    }
    if (qr_correction_level < 0 || qr_correction_level > 4)
    {
        PRINT_DBG("Invalid QR correction level\n");
        return QR_ENC_INVALID_CORRECTION_LEVEL_SPECIFIED;
    }
    if (qr_code_type < 0 || qr_code_type > 2)
    {
        PRINT_DBG("Invalid QR code type\n");
        return QR_ENC_INVALID_CODE_TYPE_SPECIFIED;
    }
    if (qr_version < VERSION_AUTO || (QR_SIZE_MICRO == qr_code_type && qr_version > 4) || (QR_SIZE_MICRO != qr_code_type && qr_version > 40))
    {
        PRINT_DBG("Invalid QR version\n");
        return QR_ENC_INVALID_VERSION_SPECIFIED;
    }
    if (QR_SIZE_AUTO == qr_code_type && VERSION_AUTO != qr_version)
    {
        PRINT_DBG("Version specified with no QR type\n");
        return QR_ENC_VERSION_REQUIRES_QR_TYPE;
    }

    // ================================================================
    // Check input types
    // ================================================================

    size_t list_capacity = EVAL_BUFFER_SIZE;
    struct encoding_run_t *encoding_list = (struct encoding_run_t *)malloc(list_capacity * sizeof(struct encoding_run_t));
    size_t list_size = 0;
    uint8_t data_types = parse_input(input_data, &encoding_list, &list_capacity, &list_size);
    if (data_types == 0)
    {
        free(encoding_list);
        return QR_ENC_INPUT_PARSING_FAILED;
    }
    int module_count = 0;
    int micro_version = (QR_SIZE_STANDARD == qr_code_type) ? 4 : min_micro_qr_version(data_types, qr_correction_level);
    enum error_correction_level_t correction_level = (CORRECTION_LEVEL_AUTO == qr_correction_level) ? CORRECTION_LEVEL_M : qr_correction_level;
    int version_index = optimise_input(micro_version, correction_level, encoding_list, &list_size, &module_count);
    if (version_index > 6)
    {
        PRINT_DBG("Error optimising input\n");
        free(encoding_list);
        return QR_ENC_DATA_EXCEEDS_QR_CAPACITY;
    }
    if (QR_SIZE_MICRO == qr_code_type)
    {
        if (version_index > 3)
        {
            PRINT_DBG("Cannot generate Micro QR\n");
            free(encoding_list);
            return QR_ENC_DATA_EXCEEDS_MICRO_QR_CAPACITY;
        }
    }
    if (QR_SIZE_STANDARD != qr_code_type && 0 == version_index)
    {
        correction_level = CORRECTION_LEVEL_L;
    }

    for (size_t i = 0; i < list_size; ++i)
    {
        PRINT_DBG("%s%lu, ", (BYTE_DATA == encoding_list[i].type) ? "B" : (KANJI_DATA == encoding_list[i].type)      ? "K"
                                                                      : (ALPHANUMERIC_DATA == encoding_list[i].type) ? "A"
                                                                                                                     : "N",
                  encoding_list[i].char_count);
    }
    PRINT_DBG("%d modules\n", module_count);

    size_t data_word_total = 0;
    size_t error_word_total = 0;
    int version = 39;
    enum code_type_t code_type = compute_data_word_sizes(correction_level, module_count, version_index, &version, &data_word_total, &error_word_total);

    if (VERSION_AUTO != qr_version)
    {
        if (version >= qr_version)
        {
            PRINT_DBG("Minimum version exceeded\n");
            free(encoding_list);
            return (QR_SIZE_STANDARD == qr_code_type) ? QR_ENC_DATA_EXCEEDS_QR_CAPACITY : QR_ENC_DATA_EXCEEDS_MICRO_QR_CAPACITY;
        }
        version = qr_version - VERSION_OFFSET;
        if (QR_SIZE_MICRO == code_type)
        {
            if (0 != version)
            {
                correction_level = (CORRECTION_LEVEL_AUTO == qr_correction_level) ? CORRECTION_LEVEL_M : qr_correction_level;
            }
            data_word_total = (size_t)(((micro_module_capacities[version][correction_level] + 4) >> 3));
            error_word_total = (size_t)micro_error_words[version][correction_level];
        }
        else
        {
            const int *const block_data = error_blocks[version][correction_level];
            data_word_total = (size_t)(block_data[GROUP_1_BLOCK_COUNT] * block_data[GROUP_1_BLOCK_SIZE] + block_data[GROUP_2_BLOCK_COUNT] * block_data[GROUP_2_BLOCK_SIZE]);
            error_word_total = (size_t)(block_data[ERR_WORDS_PER_BLOCK] * (block_data[GROUP_1_BLOCK_COUNT] + block_data[GROUP_2_BLOCK_COUNT]));
        }
    }
    PRINT_DBG("Version: %d, %s %c, %lu+%lu data+error words\n", version + VERSION_OFFSET, QR_SIZE_STANDARD == code_type ? "QR" : "MicroQR", correction_map[correction_level], data_word_total, error_word_total);

    struct buffer_t encoder_buffer = {.bit_index = 0, .byte_index = 0, .size = data_word_total + error_word_total};
    encoder_buffer.data = calloc(encoder_buffer.size, sizeof(uint8_t));
    qr_encode_input(code_type, version, correction_level, module_count, input_data, encoding_list, list_size, &encoder_buffer);
    PRINT_DBG("Encoded data: ");
    for (size_t i = 0; i < data_word_total; ++i)
    {
        PRINT_DBG("%02x ", encoder_buffer.data[i]);
    }
    PRINT_DBG("\n");

    // ================================================================
    // Error correction
    // ================================================================
    const int (*block_data)[5] = &error_blocks[version][correction_level];
    const int microqr_data[5] = {(int)error_word_total, 1, (int)data_word_total, 0, 0};
    if (QR_SIZE_MICRO == code_type)
    {
        PRINT_DBG("Micro QR ");
        block_data = &microqr_data;
    }

    qr_error_correction(code_type, version, correction_level, *block_data, &encoder_buffer, data_word_total);

    // ================================================================
    // Interleave
    // ================================================================

    int alignment_positions[ALIGNMENT_POSITIONS_MAX];
    const int n = compute_alignment_positions(version + VERSION_OFFSET, alignment_positions);
    PRINT_DBG("Free modules: %d (%d bytes)\n", qr_size(version, n), (qr_size(version, n) + 7) >> 3);
    size_t qr_data_size = ((size_t)qr_size(version, n) + 0x07u) >> 3;
    uint8_t *interleaved_data = calloc(qr_data_size, sizeof(uint8_t));
    if (QR_SIZE_MICRO == code_type)
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
        PRINT_DBG("Data: ");
    }
    else
    {
        qr_interleave(*block_data, data_word_total, &encoder_buffer, interleaved_data);
        PRINT_DBG("Interleaved data: ");
    }

    for (size_t i = 0; i < data_word_total + error_word_total; ++i)
    {
        PRINT_DBG("%02x ", interleaved_data[i]);
    }
    PRINT_DBG("\n");

    // ================================================================
    // Build Image
    // ================================================================

    size_t qr_width = (size_t)(21 + (version << 2));
    if (QR_SIZE_MICRO == code_type)
    {
        qr_width = (size_t)(11 + (version << 1));
    }

    struct buffer_t qr_buffer = {.bit_index = 0, .byte_index = 0, .size = qr_width * qr_width};
    qr_buffer.data = (uint8_t *)calloc(qr_buffer.size, sizeof(uint8_t));
    qr_setup(code_type, qr_width, n, alignment_positions, &qr_buffer);
    qr_fill(code_type, version, qr_width, interleaved_data, qr_data_size, alignment_positions, n, &qr_buffer);
    uint8_t mask_pattern_index = evaluate_masks(code_type, qr_width, &qr_buffer);
    qr_add_format(code_type, version, correction_level, mask_pattern_index, qr_width, &qr_buffer);
    if (version >= BUILD_VERSION_INFO)
    {
        qr_add_version(version, qr_width, &qr_buffer);
    }

    // ================================================================
    // Output
    // ================================================================

    size_t output_struct_size = sizeof(struct qr_data_t);
    size_t output_data_size = (size_t)(qr_width * qr_width + 0x07) >> 3;
    struct qr_data_t *qr_code_builder = *qr_code;
    free(qr_code_builder);
    qr_code_builder = calloc(output_struct_size + output_data_size, sizeof(uint8_t));
    qr_code_builder->type = code_type;
    qr_code_builder->version = version + VERSION_OFFSET;
    qr_code_builder->err_level = (QR_SIZE_MICRO == code_type && 0 == version) ? CORRECTION_LEVEL_NONE : correction_level;
    qr_code_builder->width = (int)qr_width;
    qr_code_builder->mask = mask_pattern_index;
    qr_code_builder->data = (uint8_t *)qr_code_builder + output_struct_size;
    *qr_code = qr_code_builder;

    struct buffer_t output_builder = {.bit_index = 0, .byte_index = 0, .data = qr_code_builder->data};
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

    free(qr_buffer.data);
    free(interleaved_data);
    free(encoder_buffer.data);
    free(encoding_list);
    return QR_ENC_NO_ERROR;
}
