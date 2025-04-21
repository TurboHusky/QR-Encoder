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

static void data_buffer_write(void ** /*state*/)
{
    // No bounds checking
    uint8_t buf_data[] = {0x00, 0x00, 0x00};
    struct buffer_t test_buf = {.data = buf_data, .size = sizeof(buf_data)};

    assert_uint_equal(test_buf.size, 3);
    assert_uint_equal(test_buf.data, &buf_data[0]);
    assert_uint_equal(test_buf.data[0], 0);
    assert_uint_equal(test_buf.data[1], 0);
    assert_uint_equal(test_buf.data[2], 0);

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
        assert_uint_equal(test_buf.bit_index, test_inputs[i].new_bit_index);
        assert_uint_equal(test_buf.byte_index, test_inputs[i].new_index);
    }

    // ToDo: Test buffer data is correct
}

static void data_buffer_read(void ** /*state*/)
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
        assert_uint_equal(test, results[i]);
    }
}

static void numeric_encoding(void ** /*state*/)
{
    uint8_t input_data[] = {'0', '9', '8', '7', '0', '6', '5', '4', '0', '3', '2', '1'};
    struct buffer_t input = {.data = input_data, .size = 12, .byte_index = 0};

    uint8_t output_data[8];
    struct buffer_t output = {.data = output_data, .size = 8, .byte_index = 0, .bit_index = 0};

    memset(output_data, 0, 8);
    encode_numeric(input, &output);
    uint8_t expected_data[] = {0x18, 0xAC, 0x28, 0x71, 0x41};
    assert_memory_equal(output.data, expected_data, 5);
    assert_uint_equal(output.byte_index, 5);
    assert_uint_equal(output.bit_index, 0);

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
    assert_uint_equal(output.byte_index, 3);
    assert_uint_equal(output.bit_index, 3);

    input.size = 4;
    input.byte_index = 0;
    input.bit_index = 0;
    output.byte_index = 0;
    output.bit_index = 0;
    memset(output_data, 0, 8);
    encode_numeric(input, &output);
    expected_data[1] = 0x9C;
    assert_memory_equal(output.data, expected_data, 2);
    assert_uint_equal(output.byte_index, 1);
    assert_uint_equal(output.bit_index, 6);
}

static void alphanumeric_encoding(void ** /*state*/)
{
    char *input_data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 $%*+-./:";
    struct buffer_t input = {.data = input_data, .size = 45, .byte_index = 0};

    uint8_t output_data[32];
    struct buffer_t output = {.data = output_data, .size = 32, .byte_index = 0, .bit_index = 0};

    memset(output_data, 0, 32);
    encode_alphanumeric(input, &output);
    uint8_t expected_data[] = {0x39, 0xA8, 0xA5, 0x42, 0xAE, 0x16, 0x7A, 0xE6, 0x5F, 0xAC, 0x51, 0x95, 0xB4, 0x26, 0xB2, 0xDC, 0x1C, 0x3A, 0x00, 0x42, 0xE8, 0xB9, 0x22, 0xA5, 0xC7, 0x3C, 0xED, 0x5E, 0x63, 0xE3, 0x6C};
    assert_memory_equal(output.data, expected_data, 31);
    assert_uint_equal(output.byte_index, 31);
    assert_uint_equal(output.bit_index, 0);
}

static void kanji_encoding(void ** /*stote*/)
{
    uint8_t input_data[] = {0x81, 0x40, 0x9F, 0x7E, 0x81, 0x80, 0x9F, 0xFC, 0xE0, 0x40, 0xEB, 0x7E, 0xE0, 0x80, 0xEA, 0xFC, 0xEB, 0xBF, 0x93, 0x5f, 0xE4, 0xAA};
    struct buffer_t input = {.data = input_data, .size = 22, .byte_index = 0};

    uint8_t output_data[32];
    struct buffer_t output = {.data = output_data, .size = 32, .byte_index = 0, .bit_index = 0};

    memset(output_data, 0, 32);
    encode_kanji(input, &output);
    uint8_t expected_data[] = {0x00, 0x05, 0xAF, 0x80, 0x81, 0x73, 0xCB, 0xA0, 0x7E, 0xFA, 0xF0, 0x1F, 0x7C, 0xFF, 0xFB, 0x67, 0xF5, 0x54};
    assert_memory_equal(output.data, expected_data, 18);
    assert_uint_equal(output.byte_index, 17);
    assert_uint_equal(output.bit_index, 7);
}

static void byte_encoding(void ** /*state*/)
{
    uint8_t input_data[] = {0x00, 0xFF, 0x01, 0x10, 0x80, 0x08, 0xAC};
    struct buffer_t input = {.data = input_data, .size = 7, .byte_index = 0};

    uint8_t *output_data = calloc(32, sizeof(uint8_t));
    struct buffer_t output = {.data = output_data, .size = 32, .byte_index = 0, .bit_index = 3};

    encode_byte(input, &output);
    uint8_t expected_data[] = {0x00, 0x1F, 0xE0, 0x22, 0x10, 0x01, 0x15, 0x80};
    assert_memory_equal(output.data, expected_data, 8);
    assert_uint_equal(output.byte_index, 7);
    assert_uint_equal(output.bit_index, 3);
    free(output_data);
}

static void kanji_check(const char char1, const char end)
{
    size_t count = 0;
    for (char j = '\x00'; j < '\x40'; ++j)
    {
        assert_uint_not_equal(input_type(char1, j), KANJI_DATA);
        ++count;
    }
    for (char j = '\x40'; j <= '\x7E'; ++j)
    {
        assert_uint_equal(input_type(char1, j), KANJI_DATA);
        ++count;
    }
    assert_uint_not_equal(input_type(char1, '\x7F'), KANJI_DATA);
    ++count;
    for (char j = '\x80'; j <= end; ++j)
    {
        assert_uint_equal(input_type(char1, j), KANJI_DATA);
        ++count;
    }
    for (char j = end + 1; j <= '\xFF'; ++j)
    {
        assert_uint_not_equal(input_type(char1, j), KANJI_DATA);
        ++count;
    }
}

static void type_identification(void ** /*state*/)
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

static void encoding_lengths(void ** /*state*/)
{
    assert_uint_equal(encoding_size(NUMERIC_DATA, 12), 40);
    assert_uint_equal(encoding_size(NUMERIC_DATA, 16), 54);
    assert_uint_equal(encoding_size(NUMERIC_DATA, 20), 67);
    assert_uint_equal(encoding_size(ALPHANUMERIC_DATA, 23), 127);
    assert_uint_equal(encoding_size(ALPHANUMERIC_DATA, 14), 77);
    assert_uint_equal(encoding_size(BYTE_DATA, 23), 184);
    assert_uint_equal(encoding_size(KANJI_DATA, 24), 156);
}

static void data_analysis(void ** /*state*/)
{
    // 7 header indices, 4uQR, 3 versions

    assert_int_equal(analyse_numeric_data(1, BYTE_DATA, BYTE_DATA, BYTE_DATA, 2), UNABLE_TO_MERGE);
    assert_int_equal(analyse_numeric_data(1, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, 2), UNABLE_TO_MERGE);
    assert_int_equal(analyse_numeric_data(1, KANJI_DATA, KANJI_DATA, KANJI_DATA, 2), UNABLE_TO_MERGE);
    assert_int_equal(analyse_alpha_kanji_data(1, KANJI_DATA, KANJI_DATA, BYTE_DATA, 2), UNABLE_TO_MERGE);

    int num_to_alpha_limits[6][4] = {{2, 3, 4, 5}, {2, 3, 5, 6}, {4, 5, 7, 8}, {6, 7, 12, 13}, {7, 8, 14, 15}, {8, 9, 16, 17}};

    for (int i = 0; i < 6; ++i)
    {
        assert_int_equal(analyse_numeric_data(i + 1, ALPHANUMERIC_DATA, BYTE_DATA, NUMERIC_DATA, num_to_alpha_limits[i][0]), MERGE_WITH_LAST);
        assert_int_equal(analyse_numeric_data(i + 1, ALPHANUMERIC_DATA, BYTE_DATA, NUMERIC_DATA, num_to_alpha_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(analyse_numeric_data(i + 1, BYTE_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_alpha_limits[i][0]), MERGE_WITH_NEXT);
        assert_int_equal(analyse_numeric_data(i + 1, BYTE_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_alpha_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(analyse_numeric_data(i + 1, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_alpha_limits[i][2]), MERGE_WITH_LAST);
        assert_int_equal(analyse_numeric_data(i + 1, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_alpha_limits[i][3]), DO_NOT_MERGE);
    }

    int num_to_byte_limits[5][4] = {{1, 2, 2, 3}, {1, 2, 3, 4}, {2, 3, 5, 6}, {3, 4, 7, 8}, {3, 4, 8, 9}};

    for (int i = 0; i < 5; ++i)
    {
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_byte_limits[i][0]), MERGE_WITH_LAST);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, NUMERIC_DATA, num_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, NUMERIC_DATA, num_to_byte_limits[i][0]), MERGE_WITH_NEXT);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, NUMERIC_DATA, num_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, BYTE_DATA, NUMERIC_DATA, num_to_byte_limits[i][2]), MERGE_WITH_LAST);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, BYTE_DATA, NUMERIC_DATA, num_to_byte_limits[i][3]), DO_NOT_MERGE);
    }

    int alpha_to_byte_limits[5][4] = {{2, 3, 4, 5}, {3, 4, 6, 7}, {5, 6, 9, 10}, {5, 6, 13, 14}, {6, 7, 14, 15}};

    for (int i = 0; i < 5; ++i)
    {
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][0]), MERGE_WITH_LAST);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][0]), MERGE_WITH_NEXT);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, BYTE_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][2]), MERGE_WITH_LAST);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, BYTE_DATA, ALPHANUMERIC_DATA, alpha_to_byte_limits[i][3]), DO_NOT_MERGE);
    }

    int kanji_to_byte_limits[5][4] = {{2, 4, 6, 8}, {4, 6, 8, 10}, {6, 8, 14, 16}, {8, 10, 22, 24}, {10, 12, 22, 24}};

    for (int i = 0; i < 5; ++i)
    {
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, KANJI_DATA, kanji_to_byte_limits[i][0]), MERGE_WITH_LAST);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, ALPHANUMERIC_DATA, KANJI_DATA, kanji_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, KANJI_DATA, kanji_to_byte_limits[i][0]), MERGE_WITH_NEXT);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, ALPHANUMERIC_DATA, BYTE_DATA, KANJI_DATA, kanji_to_byte_limits[i][1]), DO_NOT_MERGE);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, BYTE_DATA, KANJI_DATA, kanji_to_byte_limits[i][2]), MERGE_WITH_LAST);
        assert_int_equal(analyse_alpha_kanji_data(i + 2, BYTE_DATA, BYTE_DATA, KANJI_DATA, kanji_to_byte_limits[i][3]), DO_NOT_MERGE);
    }

    struct encoding_run_t test_list[] = {{ALPHANUMERIC_DATA, 1}, {NUMERIC_DATA, 6}, {BYTE_DATA, 4}, {ALPHANUMERIC_DATA, 2}};

    merge_data(5, test_list, 4, analyse_numeric_data);
    assert_int_equal(test_list[0].char_count, 0);
    assert_int_equal(test_list[1].type, ALPHANUMERIC_DATA);
    assert_int_equal(test_list[1].char_count, 7);

    merge_data(5, test_list, 4, analyse_alpha_kanji_data);
    assert_int_equal(test_list[2].char_count, 0);
    assert_int_equal(test_list[3].type, BYTE_DATA);
    assert_int_equal(test_list[3].char_count, 6);
}

static void error_code_generation(void ** /*state*/)
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

static void alignment_positions(void ** /*state*/)
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

static void data_capacity(void ** /*state*/)
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

static void image_fill(void ** /*state*/)
{
    uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
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

    uint8_t output_check[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 255, 255, 255, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 255, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 0, 255, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 255, 255, 255, 255, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 0, 255, 255, 255, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 255, 255, 255, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 255, 255, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 255, 255, 255, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 255, 255, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 255, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 255, 255, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 255, 255, 255, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 255, 255, 255, 0, 255, 255};

    assert_memory_equal(output, output_check, sizeof(output_check));
    free(output);
}

void mask_tests(void ** /*state*/)
{
    uint16_t pattern_buffer = EVAL_PATTERN_LEFT >> 1;
    int score = pattern_score(0, &pattern_buffer);
    assert_int_equal(score, 40);
    assert_uint_equal(pattern_buffer, EVAL_PATTERN_LEFT);

    pattern_buffer >>= 1;
    score = pattern_score(1, &pattern_buffer);
    assert_int_equal(score, 0);
    assert_uint_not_equal(pattern_buffer, EVAL_PATTERN_LEFT);

    pattern_buffer = EVAL_PATTERN_RIGHT >> 1;
    score = pattern_score(1, &pattern_buffer);
    assert_int_equal(score, 40);
    assert_uint_equal(pattern_buffer, EVAL_PATTERN_RIGHT);

    pattern_buffer >>= 1;
    score = pattern_score(0, &pattern_buffer);
    assert_int_equal(score, 0);
    assert_uint_not_equal(pattern_buffer, EVAL_PATTERN_RIGHT);

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
        cmocka_unit_test(data_buffer_write),
        cmocka_unit_test(data_buffer_read),
        cmocka_unit_test(numeric_encoding),
        cmocka_unit_test(alphanumeric_encoding),
        cmocka_unit_test(kanji_encoding),
        cmocka_unit_test(byte_encoding),
        cmocka_unit_test(type_identification),
        cmocka_unit_test(encoding_lengths),
        cmocka_unit_test(data_analysis),
        cmocka_unit_test(error_code_generation),
        cmocka_unit_test(alignment_positions),
        cmocka_unit_test(data_capacity),
        cmocka_unit_test(image_fill),
        cmocka_unit_test(mask_tests)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
