// cmocka requirements
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdlib.h>
#include "cmocka.h"

#include "../src/qr.c"

uint8_t gf256_lookup[256][2] = {
    {1, 0}, {2, 0}, {4, 1}, {8, 25}, {16, 2}, {32, 50}, {64, 26}, {128, 198}, {29, 3}, {58, 223}, {116, 51}, {232, 238}, {205, 27}, {135, 104}, {19, 199}, {38, 75}, {76, 4}, {152, 100}, {45, 224}, {90, 14}, {180, 52}, {117, 141}, {234, 239}, {201, 129}, {143, 28}, {3, 193}, {6, 105}, {12, 248}, {24, 200}, {48, 8}, {96, 76}, {192, 113}, {157, 5}, {39, 138}, {78, 101}, {156, 47}, {37, 225}, {74, 36}, {148, 15}, {53, 33}, {106, 53}, {212, 147}, {181, 142}, {119, 218}, {238, 240}, {193, 18}, {159, 130}, {35, 69}, {70, 29}, {140, 181}, {5, 194}, {10, 125}, {20, 106}, {40, 39}, {80, 249}, {160, 185}, {93, 201}, {186, 154}, {105, 9}, {210, 120}, {185, 77}, {111, 228}, {222, 114}, {161, 166}, {95, 6}, {190, 191}, {97, 139}, {194, 98}, {153, 102}, {47, 221}, {94, 48}, {188, 253}, {101, 226}, {202, 152}, {137, 37}, {15, 179}, {30, 16}, {60, 145}, {120, 34}, {240, 136}, {253, 54}, {231, 208}, {211, 148}, {187, 206}, {107, 143}, {214, 150}, {177, 219}, {127, 189}, {254, 241}, {225, 210}, {223, 19}, {163, 92}, {91, 131}, {182, 56}, {113, 70}, {226, 64}, {217, 30}, {175, 66}, {67, 182}, {134, 163}, {17, 195}, {34, 72}, {68, 126}, {136, 110}, {13, 107}, {26, 58}, {52, 40}, {104, 84}, {208, 250}, {189, 133}, {103, 186}, {206, 61}, {129, 202}, {31, 94}, {62, 155}, {124, 159}, {248, 10}, {237, 21}, {199, 121}, {147, 43}, {59, 78}, {118, 212}, {236, 229}, {197, 172}, {151, 115}, {51, 243}, {102, 167}, {204, 87}, {133, 7}, {23, 112}, {46, 192}, {92, 247}, {184, 140}, {109, 128}, {218, 99}, {169, 13}, {79, 103}, {158, 74}, {33, 222}, {66, 237}, {132, 49}, {21, 197}, {42, 254}, {84, 24}, {168, 227}, {77, 165}, {154, 153}, {41, 119}, {82, 38}, {164, 184}, {85, 180}, {170, 124}, {73, 17}, {146, 68}, {57, 146}, {114, 217}, {228, 35}, {213, 32}, {183, 137}, {115, 46}, {230, 55}, {209, 63}, {191, 209}, {99, 91}, {198, 149}, {145, 188}, {63, 207}, {126, 205}, {252, 144}, {229, 135}, {215, 151}, {179, 178}, {123, 220}, {246, 252}, {241, 190}, {255, 97}, {227, 242}, {219, 86}, {171, 211}, {75, 171}, {150, 20}, {49, 42}, {98, 93}, {196, 158}, {149, 132}, {55, 60}, {110, 57}, {220, 83}, {165, 71}, {87, 109}, {174, 65}, {65, 162}, {130, 31}, {25, 45}, {50, 67}, {100, 216}, {200, 183}, {141, 123}, {7, 164}, {14, 118}, {28, 196}, {56, 23}, {112, 73}, {224, 236}, {221, 127}, {167, 12}, {83, 111}, {166, 246}, {81, 108}, {162, 161}, {89, 59}, {178, 82}, {121, 41}, {242, 157}, {249, 85}, {239, 170}, {195, 251}, {155, 96}, {43, 134}, {86, 177}, {172, 187}, {69, 204}, {138, 62}, {9, 90}, {18, 203}, {36, 89}, {72, 95}, {144, 176}, {61, 156}, {122, 169}, {244, 160}, {245, 81}, {247, 11}, {243, 245}, {251, 22}, {235, 235}, {203, 122}, {139, 117}, {11, 44}, {22, 215}, {44, 79}, {88, 174}, {176, 213}, {125, 233}, {250, 230}, {233, 231}, {207, 173}, {131, 232}, {27, 116}, {54, 214}, {108, 244}, {216, 234}, {173, 168}, {71, 80}, {142, 88}, {1, 175}};

const int pattern_count[] = {0, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7};

static void data_buffer_write(void **state)
{
    // No bounds checking
    uint8_t buf_data[] = {0x00, 0x00, 0x00};
    struct buffer_t test_buf = {.data = buf_data, .size = sizeof(buf_data)};

    assert_int_equal(test_buf.size, 3);
    assert_int_equal(test_buf.data, &buf_data[0]);
    assert_int_equal(test_buf.data[0], 0);
    assert_int_equal(test_buf.data[1], 0);
    assert_int_equal(test_buf.data[2], 0);

    struct buff_inputs_t
    {
        size_t index;
        size_t new_index;
        int input_bit_count;
        uint8_t bit_index;
        uint8_t new_bit_index;
    } test_inputs[] = {
        {0, 1, 8, 0, 0}, {0, 0, 7, 0, 7}, {0, 1, 7, 1, 0}, {0, 0, 1, 0, 1}, {0, 1, 1, 7, 0}, {0, 0, 4, 2, 6}, {0, 4, 37, 2, 7}};

    uint16_t test_data = rand();
    for (size_t i = 0; i < 7; ++i)
    {
        test_buf.bit_index = test_inputs[i].bit_index;
        test_buf.byte_index = test_inputs[i].index;
        add_to_buffer(test_data, test_inputs[i].input_bit_count, &test_buf);
        assert_int_equal(test_buf.bit_index, test_inputs[i].new_bit_index);
        assert_int_equal(test_buf.byte_index, test_inputs[i].new_index);
    }

    // ToDo: Test buffer data is correct
}

static void data_buffer_read(void **state)
{
    // No bounds checking
    uint8_t buf_data[] = {0xC7, 0x35, 0x42};
    struct buffer_t test_buf = {.data = buf_data, .size = sizeof(buf_data)};

    test_buf.byte_index = 0;
    test_buf.bit_index = 7;
    uint8_t results[] = {0, 0, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0xFF};
    for (size_t i = 0; i < sizeof(results); ++i)
    {
        uint8_t test = read_bit_stream(&test_buf);
        assert_int_equal(test, results[i]);
    }
}

static void numeric_encoding(void **state)
{
    uint8_t input_data[] = {'0', '9', '8', '7', '0', '6', '5', '4', '0', '3', '2', '1'};
    struct buffer_t input = {.data = input_data, .size = 12, .byte_index = 0};

    uint8_t output_data[8];
    struct buffer_t output = {.data = output_data, .size = 8, .byte_index = 0, .bit_index = 0};

    memset(output_data, 0, 8);
    encode_numeric(input, &output);
    uint8_t expected_data[] = {0x18, 0xAC, 0x28, 0x71, 0x41};
    assert_memory_equal(output.data, expected_data, 5);
    assert_int_equal(output.byte_index, 5);
    assert_int_equal(output.bit_index, 0);

    input.size = 8;
    input.byte_index = 0;
    input.bit_index = 0;
    output.byte_index = 0;
    output.bit_index = 0;
    memset(output_data, 0, 8);
    encode_numeric(input, &output);
    expected_data[2] = 0x26;
    expected_data[3] = 0xC0;
    assert_memory_equal(output.data, expected_data, 4);
    assert_int_equal(output.byte_index, 3);
    assert_int_equal(output.bit_index, 3);

    input.size = 4;
    input.byte_index = 0;
    input.bit_index = 0;
    output.byte_index = 0;
    output.bit_index = 0;
    memset(output_data, 0, 8);
    encode_numeric(input, &output);
    expected_data[1] = 0x9C;
    assert_memory_equal(output.data, expected_data, 2);
    assert_int_equal(output.byte_index, 1);
    assert_int_equal(output.bit_index, 6);
}

static void alphanumeric_encoding(void **state)
{
    char *input_data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 $%*+-./:";
    struct buffer_t input = {.data = input_data, .size = 45, .byte_index = 0};

    uint8_t output_data[32];
    struct buffer_t output = {.data = output_data, .size = 32, .byte_index = 0, .bit_index = 0};

    memset(output_data, 0, 32);
    encode_alphanumeric(input, &output);
    uint8_t expected_data[] = {0x39, 0xA8, 0xA5, 0x42, 0xAE, 0x16, 0x7A, 0xE6, 0x5F, 0xAC, 0x51, 0x95, 0xB4, 0x26, 0xB2, 0xDC, 0x1C, 0x3A, 0x00, 0x42, 0xE8, 0xB9, 0x22, 0xA5, 0xC7, 0x3C, 0xED, 0x5E, 0x63, 0xE3, 0x6C};
    assert_memory_equal(output.data, expected_data, 31);
    assert_int_equal(output.byte_index, 31);
    assert_int_equal(output.bit_index, 0);
}

static void kanji_encoding(void **state)
{
    uint8_t input_data[] = {0x81, 0x40, 0x9F, 0x7E, 0x81, 0x80, 0x9F, 0xFC, 0xE0, 0x40, 0xEB, 0x7E, 0xE0, 0x80, 0xEA, 0xFC, 0xEB, 0xBF, 0x93, 0x5f, 0xE4, 0xAA};
    struct buffer_t input = {.data = input_data, .size = 22, .byte_index = 0};

    uint8_t output_data[32];
    struct buffer_t output = {.data = output_data, .size = 32, .byte_index = 0, .bit_index = 0};

    memset(output_data, 0, 32);
    encode_kanji(input, &output);
    uint8_t expected_data[] = {0x00, 0x05, 0xAF, 0x80, 0x81, 0x73, 0xCB, 0xA0, 0x7E, 0xFA, 0xF0, 0x1F, 0x7C, 0xFF, 0xFB, 0x67, 0xF5, 0x54};
    assert_memory_equal(output.data, expected_data, 18);
    assert_int_equal(output.byte_index, 17);
    assert_int_equal(output.bit_index, 7);
}

static void byte_encoding(void **state)
{
    uint8_t input_data[] = {0x00, 0xFF, 0x01, 0x10, 0x80, 0x08, 0xAC};
    struct buffer_t input = {.data = input_data, .size = 7, .byte_index = 0};

    uint8_t *output_data = calloc(32, sizeof(uint8_t));
    struct buffer_t output = {.data = output_data, .size = 32, .byte_index = 0, .bit_index = 3};

    encode_byte(input, &output);
    uint8_t expected_data[] = {0x00, 0x1F, 0xE0, 0x22, 0x10, 0x01, 0x15, 0x80};
    assert_memory_equal(output.data, expected_data, 8);
    assert_int_equal(output.byte_index, 7);
    assert_int_equal(output.bit_index, 3);
    free(output_data);
}

static void kanji_check(const char char1, const char end)
{
    size_t count = 0;
    for (char j = '\x00'; j < '\x40'; ++j)
    {
        assert_int_not_equal(input_type(char1, j), KANJI_DATA);
        ++count;
    }
    for (char j = '\x40'; j <= '\x7E'; ++j)
    {
        assert_int_equal(input_type(char1, j), KANJI_DATA);
        ++count;
    }
    assert_int_not_equal(input_type(char1, '\x7F'), KANJI_DATA);
    ++count;
    for (char j = '\x80'; j <= end; ++j)
    {
        assert_int_equal(input_type(char1, j), KANJI_DATA);
        ++count;
    }
    for (char j = end + 1; j <= '\xFF'; ++j)
    {
        assert_int_not_equal(input_type(char1, j), KANJI_DATA);
        ++count;
    }
}

static void type_identification(void **state)
{
    // 30-39 numeric
    // 41-5A, 20, 24, 25, 2A, 2B, 2D, 2E, 2F, 3A alphanumeric

    const char numeric_input[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    for (int i = 0; i < sizeof(numeric_input); ++i)
    {
        assert_int_equal(input_type(numeric_input[i], (char)rand()), NUMERIC_DATA);
    }
    const char alphanumeric_input[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', '$', '%', '*', '+', '-', '.', '/', ':'};
    for (int i = 0; i < sizeof(alphanumeric_input); ++i)
    {
        assert_int_equal(input_type(alphanumeric_input[i], (char)rand()), ALPHANUMERIC_DATA);
    }

    for (uint8_t i = 0x81; i <= 0x9F; ++i)
    {
        kanji_check((char)i, '\xFC');
    }
    for (uint8_t i = 0xE0; i <= 0xEA; ++i)
    {
        kanji_check((char)i, '\xFC');
    }
    kanji_check('\xEB', '\xBF');

    for (uint8_t i = 0x00; i <= 0x1F; ++i)
    {
        assert_int_equal(input_type((char)i, (char)rand()), BYTE_DATA);
    }
    assert_int_equal(input_type('\x21', (char)rand()), BYTE_DATA);
    assert_int_equal(input_type('\x22', (char)rand()), BYTE_DATA);
    assert_int_equal(input_type('\x23', (char)rand()), BYTE_DATA);
    assert_int_equal(input_type('\x26', (char)rand()), BYTE_DATA);
    assert_int_equal(input_type('\x27', (char)rand()), BYTE_DATA);
    assert_int_equal(input_type('\x28', (char)rand()), BYTE_DATA);
    assert_int_equal(input_type('\x29', (char)rand()), BYTE_DATA);
    assert_int_equal(input_type('\x2C', (char)rand()), BYTE_DATA);
    for (uint8_t i = 0x3B; i <= 0x40; ++i)
    {
        assert_int_equal(input_type((char)i, (char)rand()), BYTE_DATA);
    }
    for (uint8_t i = 0x5B; i <= 0x80; ++i)
    {
        assert_int_equal(input_type((char)i, (char)rand()), BYTE_DATA);
    }
    for (uint8_t i = 0xA0; i <= 0xDF; ++i)
    {
        assert_int_equal(input_type((char)i, (char)rand()), BYTE_DATA);
    }
    for (uint8_t i = 0xEC; i > 0; ++i)
    {
        assert_int_equal(input_type((char)i, (char)rand()), BYTE_DATA);
    }
}

static void encoding_lengths(void **state)
{
    assert_int_equal(encoding_size(NUMERIC_DATA, 12), 40);
    assert_int_equal(encoding_size(NUMERIC_DATA, 16), 54);
    assert_int_equal(encoding_size(NUMERIC_DATA, 20), 67);
    assert_int_equal(encoding_size(ALPHANUMERIC_DATA, 23), 127);
    assert_int_equal(encoding_size(ALPHANUMERIC_DATA, 14), 77);
    assert_int_equal(encoding_size(BYTE_DATA, 23), 184);
    assert_int_equal(encoding_size(KANJI_DATA, 24), 156);
}

static void input_parsing(void **state)
{
    const char *const basic_input = "12345";
    size_t capacity = 1;
    struct encoding_run_t *run_ptr = malloc(capacity * sizeof(struct encoding_run_t));
    struct encoding_run_t *old_ptr = run_ptr;
    size_t size = 0;
    parse_input(basic_input, &run_ptr, &capacity, &size);
    assert_int_equal(capacity, 1);
    assert_int_equal(size, 1);
    assert_int_equal(run_ptr[0].type, NUMERIC_DATA);
    assert_int_equal(run_ptr[0].char_count, 5);
    assert_ptr_equal(capacity, 1);
    free(run_ptr);

    capacity = 1;
    run_ptr = malloc(capacity * sizeof(struct encoding_run_t));
    old_ptr = run_ptr;
    size = 0;
    const char mixed_input[8] = {'A', 'B', 'C', '1', 'a', 0x93, 0x5F, '\0'};
    parse_input(mixed_input, &run_ptr, &capacity, &size);
    assert_int_equal(capacity, 4);
    assert_int_equal(size, 4);
    assert_int_equal(run_ptr[0].type, ALPHANUMERIC_DATA);
    assert_int_equal(run_ptr[0].char_count, 3);
    assert_int_equal(run_ptr[1].type, NUMERIC_DATA);
    assert_int_equal(run_ptr[1].char_count, 1);
    assert_int_equal(run_ptr[2].type, BYTE_DATA);
    assert_int_equal(run_ptr[2].char_count, 1);
    assert_int_equal(run_ptr[3].type, KANJI_DATA);
    assert_int_equal(run_ptr[3].char_count, 1);
    assert_ptr_not_equal(capacity, 2);
    free(run_ptr);
}

static void input_optimisation(void **state)
{
    // 7 header indices, 4uQR, 3 versions
    assert_int_equal(merge_to_alphanumeric(1, BYTE_DATA, BYTE_DATA, BYTE_DATA, 2), UNABLE_TO_MERGE);
    assert_int_equal(merge_to_alphanumeric(1, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, 2), UNABLE_TO_MERGE);
    assert_int_equal(merge_to_alphanumeric(1, KANJI_DATA, KANJI_DATA, KANJI_DATA, 2), UNABLE_TO_MERGE);
    assert_int_equal(merge_to_byte(1, KANJI_DATA, KANJI_DATA, BYTE_DATA, 2), UNABLE_TO_MERGE);

    int num_to_alpha_limits[6][4] = {{2, 3, 4, 5}, {2, 3, 5, 6}, {4, 5, 7, 8}, {6, 7, 12, 13}, {7, 8, 14, 15}, {8, 9, 16, 17}};

    for (int i = 0; i < 6; ++i)
    {
        assert_int_equal(merge_to_alphanumeric(i + 1, ALPHANUMERIC_DATA, BYTE_DATA, NUMERIC_DATA, num_to_alpha_limits[i][0]), MERGE_WITH_LAST);
        assert_int_equal(merge_to_alphanumeric(i + 1, ALPHANUMERIC_DATA, BYTE_DATA, NUMERIC_DATA, num_to_alpha_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(merge_to_alphanumeric(i + 1, BYTE_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_alpha_limits[i][0]), MERGE_WITH_NEXT);
        assert_int_equal(merge_to_alphanumeric(i + 1, BYTE_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_alpha_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(merge_to_alphanumeric(i + 1, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_alpha_limits[i][2]), MERGE_WITH_LAST);
        assert_int_equal(merge_to_alphanumeric(i + 1, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_alpha_limits[i][3]), DO_NOT_MERGE);
    }

    int num_to_byte_limits[5][4] = {{1, 2, 2, 3}, {1, 2, 3, 4}, {2, 3, 5, 6}, {3, 4, 7, 8}, {3, 4, 8, 9}};

    for (int i = 0; i < 5; ++i)
    {
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_byte_limits[i][0]), MERGE_WITH_LAST);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(merge_to_byte(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, NUMERIC_DATA, num_to_byte_limits[i][0]), MERGE_WITH_NEXT);
        assert_int_equal(merge_to_byte(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, NUMERIC_DATA, num_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, BYTE_DATA, NUMERIC_DATA, num_to_byte_limits[i][2]), MERGE_WITH_LAST);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, BYTE_DATA, NUMERIC_DATA, num_to_byte_limits[i][3]), DO_NOT_MERGE);
    }

    int alpha_to_byte_limits[5][4] = {{2, 3, 4, 5}, {3, 4, 6, 7}, {5, 6, 9, 10}, {5, 6, 13, 14}, {6, 7, 14, 15}};

    for (int i = 0; i < 5; ++i)
    {
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][0]), MERGE_WITH_LAST);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(merge_to_byte(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][0]), MERGE_WITH_NEXT);
        assert_int_equal(merge_to_byte(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, BYTE_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][2]), MERGE_WITH_LAST);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, BYTE_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][3]), DO_NOT_MERGE);
    }

    int kanji_to_byte_limits[5][4] = {{2, 4, 6, 8}, {4, 6, 8, 10}, {6, 8, 14, 16}, {8, 10, 22, 24}, {10, 12, 22, 24}};

    for (int i = 0; i < 5; ++i)
    {
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, KANJI_DATA, kanji_to_byte_limits[i][0]), MERGE_WITH_LAST);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, KANJI_DATA, kanji_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(merge_to_byte(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, KANJI_DATA, kanji_to_byte_limits[i][0]), MERGE_WITH_NEXT);
        assert_int_equal(merge_to_byte(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, KANJI_DATA, kanji_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, BYTE_DATA, KANJI_DATA, kanji_to_byte_limits[i][2]), MERGE_WITH_LAST);
        assert_int_equal(merge_to_byte(i + 2, BYTE_DATA, BYTE_DATA, KANJI_DATA, kanji_to_byte_limits[i][3]), DO_NOT_MERGE);
    }

    // Merge data to minimise bits required
    size_t n_to_a[6][2] = {{3, 5}, {3, 6}, {5, 8}, {7, 13}, {8, 15}, {9, 17}};
    for (int i = 0; i < 6; ++i)
    {
        struct encoding_run_t merge[] = {{ALPHANUMERIC_DATA, 1}, {NUMERIC_DATA, n_to_a[i][1] - 1}, {ALPHANUMERIC_DATA, 1}, {NUMERIC_DATA, n_to_a[i][0] - 1}, {BYTE_DATA, 1}};
        struct encoding_run_t no_merge[] = {{ALPHANUMERIC_DATA, 1}, {NUMERIC_DATA, n_to_a[i][1]}, {ALPHANUMERIC_DATA, 1}, {NUMERIC_DATA, n_to_a[i][0]}, {BYTE_DATA, 1}};
        merge_data(i + 1, merge, 5, merge_to_alphanumeric);
        merge_data(i + 1, no_merge, 5, merge_to_alphanumeric);
        assert_int_equal(merge[0].char_count, 0);
        assert_int_equal(merge[1].char_count, 0);
        assert_int_equal(merge[2].char_count, 0);
        assert_int_equal(merge[3].type, ALPHANUMERIC_DATA);
        assert_int_equal(merge[3].char_count, n_to_a[i][0] + n_to_a[i][1]);
        assert_int_equal(merge[4].type, BYTE_DATA);
        assert_int_equal(merge[4].char_count, 1);
        assert_int_equal(no_merge[0].type, ALPHANUMERIC_DATA);
        assert_int_equal(no_merge[0].char_count, 1);
        assert_int_equal(no_merge[1].type, NUMERIC_DATA);
        assert_int_equal(no_merge[1].char_count, n_to_a[i][1]);
        assert_int_equal(no_merge[2].type, ALPHANUMERIC_DATA);
        assert_int_equal(no_merge[2].char_count, 1);
        assert_int_equal(no_merge[3].type, NUMERIC_DATA);
        assert_int_equal(no_merge[3].char_count, n_to_a[i][0]);
        assert_int_equal(no_merge[4].type, BYTE_DATA);
        assert_int_equal(no_merge[4].char_count, 1);
    }

    size_t n_to_b[5][2] = {{2, 3}, {2, 4}, {3, 6}, {4, 8}, {4, 9}};
    for (int i = 0; i < 5; ++i)
    {
        struct encoding_run_t merge[] = {{BYTE_DATA, 1}, {NUMERIC_DATA, n_to_b[i][1] - 1}, {BYTE_DATA, 1}, {NUMERIC_DATA, n_to_b[i][0] - 1}, {KANJI_DATA, 50}};
        struct encoding_run_t no_merge[] = {{BYTE_DATA, 1}, {NUMERIC_DATA, n_to_b[i][1]}, {BYTE_DATA, 1}, {NUMERIC_DATA, n_to_b[i][0]}, {KANJI_DATA, 50}};
        merge_data(i + 2, merge, 5, merge_to_byte);
        merge_data(i + 2, no_merge, 5, merge_to_byte);
        assert_int_equal(merge[0].char_count, 0);
        assert_int_equal(merge[1].char_count, 0);
        assert_int_equal(merge[2].char_count, 0);
        assert_int_equal(merge[3].type, BYTE_DATA);
        assert_int_equal(merge[3].char_count, n_to_b[i][0] + n_to_b[i][1]);
        assert_int_equal(merge[4].type, KANJI_DATA);
        assert_int_equal(merge[4].char_count, 50);
        assert_int_equal(no_merge[0].type, BYTE_DATA);
        assert_int_equal(no_merge[0].char_count, 1);
        assert_int_equal(no_merge[1].type, NUMERIC_DATA);
        assert_int_equal(no_merge[1].char_count, n_to_b[i][1]);
        assert_int_equal(no_merge[2].type, BYTE_DATA);
        assert_int_equal(no_merge[2].char_count, 1);
        assert_int_equal(no_merge[3].type, NUMERIC_DATA);
        assert_int_equal(no_merge[3].char_count, n_to_b[i][0]);
        assert_int_equal(no_merge[4].type, KANJI_DATA);
        assert_int_equal(no_merge[4].char_count, 50);
    }

    size_t a_to_b[5][2] = {{3, 5}, {4, 7}, {6, 10}, {6, 14}, {7, 15}};
    for (int i = 0; i < 5; ++i)
    {
        struct encoding_run_t merge[] = {{BYTE_DATA, 1}, {ALPHANUMERIC_DATA, a_to_b[i][1] - 1}, {BYTE_DATA, 1}, {ALPHANUMERIC_DATA, a_to_b[i][0] - 1}, {KANJI_DATA, 50}};
        struct encoding_run_t no_merge[] = {{BYTE_DATA, 1}, {ALPHANUMERIC_DATA, a_to_b[i][1]}, {BYTE_DATA, 1}, {ALPHANUMERIC_DATA, a_to_b[i][0]}, {KANJI_DATA, 50}};
        merge_data(i + 2, merge, 5, merge_to_byte);
        merge_data(i + 2, no_merge, 5, merge_to_byte);
        assert_int_equal(merge[0].char_count, 0);
        assert_int_equal(merge[1].char_count, 0);
        assert_int_equal(merge[2].char_count, 0);
        assert_int_equal(merge[3].type, BYTE_DATA);
        assert_int_equal(merge[3].char_count, a_to_b[i][0] + a_to_b[i][1]);
        assert_int_equal(merge[4].type, KANJI_DATA);
        assert_int_equal(merge[4].char_count, 50);
        assert_int_equal(no_merge[0].type, BYTE_DATA);
        assert_int_equal(no_merge[0].char_count, 1);
        assert_int_equal(no_merge[1].type, ALPHANUMERIC_DATA);
        assert_int_equal(no_merge[1].char_count, a_to_b[i][1]);
        assert_int_equal(no_merge[2].type, BYTE_DATA);
        assert_int_equal(no_merge[2].char_count, 1);
        assert_int_equal(no_merge[3].type, ALPHANUMERIC_DATA);
        assert_int_equal(no_merge[3].char_count, a_to_b[i][0]);
        assert_int_equal(no_merge[4].type, KANJI_DATA);
        assert_int_equal(no_merge[4].char_count, 50);
    }

    size_t k_to_b[5][2] = {{4, 8}, {6, 10}, {8, 16}, {10, 24}, {12, 24}};
    for (int i = 0; i < 5; ++i)
    {
        struct encoding_run_t merge[] = {{BYTE_DATA, 1}, {KANJI_DATA, k_to_b[i][1] - 2}, {BYTE_DATA, 1}, {KANJI_DATA, k_to_b[i][0] - 2}, {NUMERIC_DATA, 10}};
        struct encoding_run_t no_merge[] = {{BYTE_DATA, 1}, {KANJI_DATA, k_to_b[i][1]}, {BYTE_DATA, 1}, {KANJI_DATA, k_to_b[i][0]}, {NUMERIC_DATA, 10}};
        merge_data(i + 2, merge, 5, merge_to_byte);
        merge_data(i + 2, no_merge, 5, merge_to_byte);
        assert_int_equal(merge[0].char_count, 0);
        assert_int_equal(merge[1].char_count, 0);
        assert_int_equal(merge[2].char_count, 0);
        assert_int_equal(merge[3].type, BYTE_DATA);
        assert_int_equal(merge[3].char_count, k_to_b[i][0] + k_to_b[i][1] - 2);
        assert_int_equal(merge[4].type, NUMERIC_DATA);
        assert_int_equal(merge[4].char_count, 10);
        assert_int_equal(no_merge[0].type, BYTE_DATA);
        assert_int_equal(no_merge[0].char_count, 1);
        assert_int_equal(no_merge[1].type, KANJI_DATA);
        assert_int_equal(no_merge[1].char_count, k_to_b[i][1]);
        assert_int_equal(no_merge[2].type, BYTE_DATA);
        assert_int_equal(no_merge[2].char_count, 1);
        assert_int_equal(no_merge[3].type, KANJI_DATA);
        assert_int_equal(no_merge[3].char_count, k_to_b[i][0]);
        assert_int_equal(no_merge[4].type, NUMERIC_DATA);
        assert_int_equal(no_merge[4].char_count, 10);
    }

    // Determine correct QR type for input
    uint8_t data_types[5] = {NUMERIC_MASK, NUMERIC_MASK | ALPHANUMERIC_MASK, KANJI_MASK, BYTE_MASK, BYTE_MASK};
    uint8_t correction_levels[5] = {CORRECTION_LEVEL_L, CORRECTION_LEVEL_L, CORRECTION_LEVEL_L, CORRECTION_LEVEL_Q, CORRECTION_LEVEL_H};
    struct encoding_run_t input[5] = {{NUMERIC_DATA, 5}, {ALPHANUMERIC_DATA, 5}, {KANJI_DATA, 4}, {BYTE_DATA, 4}, {BYTE_DATA, 10}};
    int headers[5] = {0,1,2,3,4};
    for (int i = 0; i < 5; ++i)
    {
        struct encoding_run_t output[5];
        int module_count = 0;
        int header = optimise_input(&input[i], 1, correction_levels[i], data_types[i], output, &module_count);
        assert_int_equal(header, headers[i]);
    }
}

static void error_code_generation(void **state)
{
    // void calculate_error_codes(const int data_word_count, const int error_word_count, const uint8_t (*const gf256_lookup)[2], const int generator_start, const int generator_end, const uint8_t *const generator, const uint8_t *const input, uint8_t *error_words)

    uint8_t input[] = {32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17, 236, 17, 236};
    uint8_t generator[] = {1, 127, 122, 154, 164, 11, 68, 117};
    uint8_t error_words[7];
    uint8_t error_codes[7] = {0xD1, 0xEF, 0xC4, 0xCF, 0x4E, 0xC3, 0x6D};

    calculate_error_codes(19, 7, gf256_lookup, 0, 7, generator, input, error_words);
    assert_memory_equal(error_words, error_codes, 7);

    uint8_t in[] = {32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17};
    uint8_t gen[] = {1, 252, 9, 28, 13, 18, 251, 208, 150, 103, 174, 100, 41, 167, 12, 247, 56, 117, 119, 233, 127, 181, 100, 121, 147, 176, 74, 58, 197};
    uint8_t err_words[28];
    uint8_t err_codes[28] = {0xA0, 0x48, 0xF9, 0x23, 0x0A, 0x06, 0xC3, 0x1F, 0x5E, 0x1B, 0x71, 0x25, 0x7C, 0x91, 0x42, 0x5A, 0x36, 0xA8, 0x38, 0xA2, 0x02, 0x4D, 0xA2, 0x29, 0xA3, 0xF3, 0x77, 0x25};

    calculate_error_codes(16, 28, gf256_lookup, 0, 28, gen, in, err_words);
    assert_memory_equal(err_words, err_codes, 28);
}

static void alignment_positions(void **state)
{
    int alignment_positions[ALIGNMENT_POSITIONS_MAX] = {0, 0, 0, 0, 0, 0, 0};
    assert_int_equal(compute_alignment_positions(0, alignment_positions), 0);
    const int expected_coords[40][7] = {
        {0, 0, 0, 0, 0, 0, 0},
        {6, 18, 0, 0, 0, 0, 0},
        {6, 22, 0, 0, 0, 0, 0},
        {6, 26, 0, 0, 0, 0, 0},
        {6, 30, 0, 0, 0, 0, 0},
        {6, 34, 0, 0, 0, 0, 0},
        {6, 22, 38, 0, 0, 0, 0},
        {6, 24, 42, 0, 0, 0, 0},
        {6, 26, 46, 0, 0, 0, 0},
        {6, 28, 50, 0, 0, 0, 0},
        {6, 30, 54, 0, 0, 0, 0},
        {6, 32, 58, 0, 0, 0, 0},
        {6, 34, 62, 0, 0, 0, 0},
        {6, 26, 46, 66, 0, 0, 0},
        {6, 26, 48, 70, 0, 0, 0},
        {6, 26, 50, 74, 0, 0, 0},
        {6, 30, 54, 78, 0, 0, 0},
        {6, 30, 56, 82, 0, 0, 0},
        {6, 30, 58, 86, 0, 0, 0},
        {6, 34, 62, 90, 0, 0, 0},
        {6, 28, 50, 72, 94, 0, 0},
        {6, 26, 50, 74, 98, 0, 0},
        {6, 30, 54, 78, 102, 0, 0},
        {6, 28, 54, 80, 106, 0, 0},
        {6, 32, 58, 84, 110, 0, 0},
        {6, 30, 58, 86, 114, 0, 0},
        {6, 34, 62, 90, 118, 0, 0},
        {6, 26, 50, 74, 98, 122, 0},
        {6, 30, 54, 78, 102, 126, 0},
        {6, 26, 52, 78, 104, 130, 0},
        {6, 30, 56, 82, 108, 134, 0},
        {6, 34, 60, 86, 112, 138, 0},
        {6, 30, 58, 86, 114, 142, 0},
        {6, 34, 62, 90, 118, 146, 0},
        {6, 30, 54, 78, 102, 126, 150},
        {6, 24, 50, 76, 102, 128, 154},
        {6, 28, 54, 80, 106, 132, 158},
        {6, 32, 58, 84, 110, 136, 162},
        {6, 26, 54, 82, 110, 138, 166},
        {6, 30, 58, 86, 114, 142, 170}};

    for (int version = 0; version < 40; ++version)
    {
        const int n = compute_alignment_positions(version + VERSION_OFFSET, alignment_positions);
        assert_int_equal(n, pattern_count[version]);
        assert_memory_equal(alignment_positions, expected_coords[version], 7);
    }
}

static void data_capacity(void **state)
{
    int free_modules[] = {
        208, 359, 567, 807, 1079, 1383, 1568, 1936, 2336, 2768, 3232, 3728, 4256, 4651, 5243, 5867, 6523, 7211, 7931, 8683,
        9252, 10068, 10916, 11796, 12708, 13652, 14628, 15371, 16411, 17483, 18587, 19723, 20891, 22091, 23008, 24272, 25568, 26896, 28256, 29648};

    for (int version = 0; version < 40; ++version)
    {
        int size = qr_size(version, pattern_count[version]);
        assert_int_equal(size, free_modules[version]);
    }
}

static void image_fill(void **state)
{
    uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48};
    struct buffer_t input = {.bit_index = 7, .byte_index = 0, .data = data, .size = sizeof(data)};
    int alignment_positions[ALIGNMENT_POSITIONS_MAX] = {6, 22, 38, 0, 0, 0, 0};

    int width = 45;
    struct fill_settings_t settings = {.qr_width = width, .alignment.size = 3, .alignment.positions = alignment_positions};
    uint8_t *output = calloc(width * width, sizeof(uint8_t));
    memset(settings.masks, 0, 144 * sizeof(uint8_t));
    memset(output, 0, width * width * sizeof(uint8_t));
    fill_u(&input, width - 1, 9, width - 1, 1, settings.alignment.size - 1, &settings, output);
    fill_d(&input, width - 3, 9, width - 1, 1, settings.alignment.size - 1, &settings, output);
    fill_u(&input, width - 5, 9, width - 1, 1, settings.alignment.size - 1, &settings, output);
    fill_d(&input, width - 7, 9, width - 1, 1, settings.alignment.size - 1, &settings, output);
    fill_u(&input, width - 9, 7, width - 1, 1, settings.alignment.size - 1, &settings, output);
    fill_d(&input, 20, 7, width - 1, 0, settings.alignment.size - 1, &settings, output);

    uint8_t output_check[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 255, 255, 255, 0, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 255, 255, 0, 255, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 255, 255, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 255, 0, 255, 255, 255, 255, 255, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 255, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 255, 255, 255, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255, 0, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 255, 0, 255, 255, 255, 0, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 255, 255, 0, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 255, 255, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 255, 0, 255, 255, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 255, 255, 255, 0, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 255, 255, 255, 0, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 255, 0, 255, 255, 255, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 0, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 255, 255, 255, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 255, 255, 0, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 255, 255, 0, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 255, 255, 255, 0, 255, 255};

    assert_memory_equal(output, output_check, sizeof(output_check));
    free(output);
}

static void gf256_lookup_generator(void **state)
{
    uint8_t log[256] = {0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52, 141, 239, 129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218, 240, 18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166, 6, 191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136, 54, 208, 148, 206, 143, 150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250, 133, 186, 61, 202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87, 7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165, 153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57, 83, 71, 109, 65, 162, 31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246, 108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90, 203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215, 79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175};
    uint8_t antilog[256] = {1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161, 95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 0};
    uint8_t gf256_285[256][2];
    GenerateGF256Lookup(gf256_285);
    for (int i = 0; i < 256; ++i)
    {
        assert_int_equal(gf256_285[i][GF256_ANTILOG], antilog[i]);
        assert_int_equal(gf256_285[i][GF256_LOG], log[i]);
    }
}

static void error_polynomial_generator(void **state)
{
    // Converted from Table A.1 of ISO-IEC-18004
    uint8_t error_polynomials[] = {
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 2,
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 31, 198, 63, 147, 116,
        6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 63, 1, 218, 32, 227, 38,
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 127, 122, 154, 164, 11, 68, 117,
        8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 11, 81, 54, 239, 173, 200, 24,
        10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 216, 194, 159, 111, 199, 94, 95, 113, 157, 193,
        13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 137, 73, 227, 17, 177, 17, 52, 13, 46, 43, 83, 132, 120,
        14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 14, 54, 114, 70, 174, 151, 43, 158, 195, 127, 166, 210, 234, 163,
        15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 29, 196, 111, 163, 112, 74, 10, 105, 105, 139, 132, 151, 32, 134, 26,
        16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 59, 13, 104, 189, 68, 209, 30, 8, 163, 65, 41, 229, 98, 50, 36, 59,
        17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 119, 66, 83, 120, 119, 22, 197, 83, 249, 41, 143, 134, 85, 53, 125, 99, 79,
        18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 239, 251, 183, 113, 149, 175, 199, 215, 240, 220, 73, 82, 173, 75, 32, 67, 217, 146,
        20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 152, 185, 240, 5, 111, 99, 6, 220, 112, 150, 69, 36, 187, 22, 228, 198, 121, 121, 165, 174,
        22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 89, 179, 131, 176, 182, 244, 19, 189, 69, 40, 28, 137, 29, 123, 67, 253, 86, 218, 230, 26, 145, 245,
        24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 122, 118, 169, 70, 178, 237, 216, 102, 115, 150, 229, 73, 130, 72, 61, 43, 206, 1, 237, 247, 127, 217, 144, 117,
        26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 246, 51, 183, 4, 136, 98, 199, 152, 77, 56, 206, 24, 145, 40, 209, 117, 233, 42, 135, 68, 70, 144, 146, 77, 43, 94,
        28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 252, 9, 28, 13, 18, 251, 208, 150, 103, 174, 100, 41, 167, 12, 247, 56, 117, 119, 233, 127, 181, 100, 121, 147, 176, 74, 58, 197,
        30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 212, 246, 77, 73, 195, 192, 75, 98, 5, 70, 103, 177, 22, 217, 138, 51, 181, 246, 72, 25, 18, 46, 228, 74, 216, 195, 11, 106, 130, 150,
        32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 116, 64, 52, 174, 54, 126, 16, 194, 162, 33, 33, 157, 176, 197, 225, 12, 59, 55, 253, 228, 148, 47, 179, 185, 24, 138, 253, 20, 142, 55, 172, 88,
        34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 206, 60, 154, 113, 6, 117, 208, 90, 26, 113, 31, 25, 177, 132, 99, 51, 105, 183, 122, 22, 43, 136, 93, 94, 62, 111, 196, 23, 126, 135, 67, 222, 23, 10,
        36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 28, 196, 67, 76, 123, 192, 207, 251, 185, 73, 124, 1, 126, 73, 31, 27, 11, 104, 45, 161, 43, 74, 127, 89, 26, 219, 59, 137, 118, 200, 237, 216, 31, 243, 96, 59,
        40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 210, 248, 240, 209, 173, 67, 133, 167, 133, 209, 131, 186, 99, 93, 235, 52, 40, 6, 220, 241, 72, 13, 215, 128, 255, 156, 49, 62, 254, 212, 35, 99, 51, 218, 101, 180, 247, 40, 156, 38,
        42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 108, 136, 69, 244, 3, 45, 158, 245, 1, 8, 105, 176, 69, 65, 103, 107, 244, 29, 165, 52, 217, 41, 38, 92, 66, 78, 34, 9, 53, 34, 242, 14, 139, 142, 56, 197, 179, 191, 50, 237, 5, 217,
        44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 174, 128, 111, 118, 188, 207, 47, 160, 252, 165, 225, 125, 65, 3, 101, 197, 58, 77, 19, 131, 2, 11, 238, 120, 84, 222, 18, 102, 199, 62, 153, 99, 20, 50, 155, 41, 221, 229, 74, 46, 31, 68, 202, 49,
        46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 129, 113, 254, 129, 71, 18, 112, 124, 220, 134, 225, 32, 80, 31, 23, 238, 105, 76, 169, 195, 229, 178, 37, 2, 16, 217, 185, 88, 202, 13, 251, 29, 54, 233, 147, 241, 20, 3, 213, 18, 119, 112, 9, 90, 211, 38,
        48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 61, 3, 200, 46, 178, 154, 185, 143, 216, 223, 53, 68, 44, 111, 171, 161, 159, 197, 124, 45, 69, 206, 169, 230, 98, 167, 104, 83, 226, 85, 59, 149, 163, 117, 131, 228, 132, 11, 65, 232, 113, 144, 107, 5, 99, 53, 78, 208,
        50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 247, 51, 213, 209, 198, 58, 199, 159, 162, 134, 224, 25, 156, 8, 162, 206, 100, 176, 224, 36, 159, 135, 157, 230, 102, 162, 46, 230, 176, 239, 176, 15, 60, 181, 87, 157, 31, 190, 151, 47, 61, 62, 235, 255, 151, 215, 239, 247, 109, 167,
        52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 248, 5, 177, 110, 5, 172, 216, 225, 130, 159, 177, 204, 151, 90, 149, 243, 170, 239, 234, 19, 210, 77, 74, 176, 224, 218, 142, 225, 174, 113, 210, 190, 151, 31, 17, 243, 235, 118, 234, 30, 177, 175, 53, 176, 28, 172, 34, 39, 22, 142, 248, 10,
        54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 196, 6, 56, 127, 89, 69, 31, 117, 159, 190, 193, 5, 11, 149, 54, 36, 68, 105, 162, 43, 189, 145, 6, 226, 149, 130, 20, 233, 156, 142, 11, 255, 123, 240, 197, 3, 236, 119, 59, 208, 239, 253, 133, 56, 235, 29, 146, 210, 34, 192, 7, 30, 192, 228,
        56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 52, 59, 104, 213, 198, 195, 129, 248, 4, 163, 27, 99, 37, 56, 112, 122, 64, 168, 142, 114, 169, 81, 215, 162, 205, 66, 204, 42, 98, 54, 219, 241, 174, 24, 116, 214, 22, 149, 34, 151, 73, 83, 217, 201, 99, 111, 12, 200, 131, 170, 57, 112, 166, 180, 111, 116,
        58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 211, 248, 6, 131, 97, 12, 222, 104, 173, 98, 28, 55, 235, 160, 216, 176, 89, 168, 57, 139, 227, 21, 130, 27, 73, 54, 83, 214, 71, 42, 190, 145, 51, 201, 143, 96, 236, 44, 249, 64, 23, 43, 48, 77, 204, 218, 83, 233, 237, 48, 212, 161, 115, 42, 243, 51, 82, 197,
        60, 0, 0, 0, 0, 0, 0, 0, 0, 1, 104, 132, 6, 205, 58, 21, 125, 141, 72, 141, 86, 193, 178, 34, 86, 59, 24, 49, 204, 64, 17, 131, 4, 167, 7, 186, 124, 86, 34, 189, 230, 211, 74, 148, 11, 140, 230, 162, 118, 177, 232, 151, 96, 49, 107, 3, 50, 127, 190, 68, 174, 172, 94, 12, 162, 76, 225, 128, 39, 44,
        62, 0, 0, 0, 0, 0, 0, 1, 190, 112, 31, 67, 188, 9, 27, 199, 249, 113, 1, 236, 74, 201, 4, 61, 105, 118, 128, 26, 169, 120, 125, 199, 94, 30, 9, 225, 101, 5, 94, 206, 50, 152, 121, 102, 49, 156, 69, 237, 235, 232, 122, 164, 41, 197, 242, 106, 124, 64, 28, 17, 6, 207, 98, 43, 204, 239, 37, 110, 103, 52,
        64, 0, 0, 0, 0, 1, 193, 10, 255, 58, 128, 183, 115, 140, 153, 147, 91, 197, 219, 221, 220, 142, 28, 120, 21, 164, 147, 6, 204, 40, 230, 182, 14, 121, 48, 143, 77, 228, 81, 85, 43, 162, 16, 195, 163, 35, 149, 154, 35, 132, 100, 100, 51, 176, 11, 161, 134, 208, 132, 244, 176, 192, 221, 232, 171, 125, 155, 228, 242, 245,
        66, 0, 0, 1, 32, 199, 138, 150, 79, 79, 191, 10, 159, 237, 135, 239, 231, 152, 66, 131, 141, 179, 226, 246, 190, 158, 171, 153, 206, 226, 34, 212, 101, 249, 229, 141, 226, 128, 238, 57, 60, 206, 203, 106, 118, 84, 161, 127, 253, 71, 44, 102, 155, 60, 78, 247, 52, 5, 252, 211, 30, 154, 194, 52, 179, 3, 184, 182, 193, 26,
        68, 1, 131, 115, 9, 39, 18, 182, 60, 94, 223, 230, 157, 142, 119, 85, 107, 34, 174, 167, 109, 20, 185, 112, 145, 172, 224, 170, 182, 107, 38, 107, 71, 246, 230, 225, 144, 20, 14, 175, 226, 245, 20, 219, 212, 51, 158, 88, 63, 36, 199, 4, 80, 157, 211, 239, 255, 7, 119, 11, 235, 12, 34, 149, 204, 8, 32, 29, 99, 11};

    for (int i = 0; i < 36; ++i)
    {
        uint8_t gf256_285[256][2];
        uint8_t *polynomial = calloc(69, sizeof(uint8_t));
        GenerateGF256Lookup(gf256_285);
        for (int i = 0; i < 36; ++i)
        {
            GenerateErrorPolynomial(error_polynomials[i * 70], gf256_285, polynomial + 68 - error_polynomials[i * 70]);
            assert_memory_equal(error_polynomials + i * 70 + 1, polynomial, 69);
        }
        free(polynomial);
    }
}

void mask_tests(void **state)
{
    uint16_t pattern_buffer = EVAL_PATTERN_LEFT >> 1;
    int score = pattern_score(0, &pattern_buffer);
    assert_int_equal(score, 40);
    assert_int_equal(pattern_buffer, EVAL_PATTERN_LEFT);

    pattern_buffer >>= 1;
    score = pattern_score(1, &pattern_buffer);
    assert_int_equal(score, 0);
    assert_int_not_equal(pattern_buffer, EVAL_PATTERN_LEFT);

    pattern_buffer = EVAL_PATTERN_RIGHT >> 1;
    score = pattern_score(1, &pattern_buffer);
    assert_int_equal(score, 40);
    assert_int_equal(pattern_buffer, EVAL_PATTERN_RIGHT);

    pattern_buffer >>= 1;
    score = pattern_score(0, &pattern_buffer);
    assert_int_equal(score, 0);
    assert_int_not_equal(pattern_buffer, EVAL_PATTERN_RIGHT);

    int run = 0;
    int last = 0;

    for (int i = 1; i < 20; ++i)
    {
        score = repeat_score(0, &last, &run);
        assert_int_equal(score, 0);
        assert_int_equal(run, i);
    }

    score = repeat_score(1, &last, &run);
    assert_int_equal(score, 17);
    assert_int_equal(run, 1);

    for (int i = 2; i < 25; ++i)
    {
        score = repeat_score(1, &last, &run);
        assert_int_equal(score, 0);
        assert_int_equal(run, i);
    }

    score = repeat_score(0, &last, &run);
    assert_int_equal(score, 22);
    assert_int_equal(run, 1);
}

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(input_parsing),
        cmocka_unit_test(data_buffer_write),
        cmocka_unit_test(data_buffer_read),
        cmocka_unit_test(numeric_encoding),
        cmocka_unit_test(alphanumeric_encoding),
        cmocka_unit_test(kanji_encoding),
        cmocka_unit_test(byte_encoding),
        cmocka_unit_test(type_identification),
        cmocka_unit_test(encoding_lengths),
        cmocka_unit_test(input_optimisation),
        cmocka_unit_test(error_code_generation),
        cmocka_unit_test(alignment_positions),
        cmocka_unit_test(data_capacity),
        cmocka_unit_test(image_fill),
        cmocka_unit_test(mask_tests),
        cmocka_unit_test(gf256_lookup_generator),
        cmocka_unit_test(error_polynomial_generator)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
