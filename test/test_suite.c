// cmocka requirements
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdlib.h>
#include <time.h>
#include "cmocka.h"

#include "../src/qr.c"

uint8_t gf256_lookup[256][2] = {
    {1, 0}, {2, 0}, {4, 1}, {8, 25}, {16, 2}, {32, 50}, {64, 26}, {128, 198}, {29, 3}, {58, 223}, {116, 51}, {232, 238}, {205, 27}, {135, 104}, {19, 199}, {38, 75}, {76, 4}, {152, 100}, {45, 224}, {90, 14}, {180, 52}, {117, 141}, {234, 239}, {201, 129}, {143, 28}, {3, 193}, {6, 105}, {12, 248}, {24, 200}, {48, 8}, {96, 76}, {192, 113}, {157, 5}, {39, 138}, {78, 101}, {156, 47}, {37, 225}, {74, 36}, {148, 15}, {53, 33}, {106, 53}, {212, 147}, {181, 142}, {119, 218}, {238, 240}, {193, 18}, {159, 130}, {35, 69}, {70, 29}, {140, 181}, {5, 194}, {10, 125}, {20, 106}, {40, 39}, {80, 249}, {160, 185}, {93, 201}, {186, 154}, {105, 9}, {210, 120}, {185, 77}, {111, 228}, {222, 114}, {161, 166}, {95, 6}, {190, 191}, {97, 139}, {194, 98}, {153, 102}, {47, 221}, {94, 48}, {188, 253}, {101, 226}, {202, 152}, {137, 37}, {15, 179}, {30, 16}, {60, 145}, {120, 34}, {240, 136}, {253, 54}, {231, 208}, {211, 148}, {187, 206}, {107, 143}, {214, 150}, {177, 219}, {127, 189}, {254, 241}, {225, 210}, {223, 19}, {163, 92}, {91, 131}, {182, 56}, {113, 70}, {226, 64}, {217, 30}, {175, 66}, {67, 182}, {134, 163}, {17, 195}, {34, 72}, {68, 126}, {136, 110}, {13, 107}, {26, 58}, {52, 40}, {104, 84}, {208, 250}, {189, 133}, {103, 186}, {206, 61}, {129, 202}, {31, 94}, {62, 155}, {124, 159}, {248, 10}, {237, 21}, {199, 121}, {147, 43}, {59, 78}, {118, 212}, {236, 229}, {197, 172}, {151, 115}, {51, 243}, {102, 167}, {204, 87}, {133, 7}, {23, 112}, {46, 192}, {92, 247}, {184, 140}, {109, 128}, {218, 99}, {169, 13}, {79, 103}, {158, 74}, {33, 222}, {66, 237}, {132, 49}, {21, 197}, {42, 254}, {84, 24}, {168, 227}, {77, 165}, {154, 153}, {41, 119}, {82, 38}, {164, 184}, {85, 180}, {170, 124}, {73, 17}, {146, 68}, {57, 146}, {114, 217}, {228, 35}, {213, 32}, {183, 137}, {115, 46}, {230, 55}, {209, 63}, {191, 209}, {99, 91}, {198, 149}, {145, 188}, {63, 207}, {126, 205}, {252, 144}, {229, 135}, {215, 151}, {179, 178}, {123, 220}, {246, 252}, {241, 190}, {255, 97}, {227, 242}, {219, 86}, {171, 211}, {75, 171}, {150, 20}, {49, 42}, {98, 93}, {196, 158}, {149, 132}, {55, 60}, {110, 57}, {220, 83}, {165, 71}, {87, 109}, {174, 65}, {65, 162}, {130, 31}, {25, 45}, {50, 67}, {100, 216}, {200, 183}, {141, 123}, {7, 164}, {14, 118}, {28, 196}, {56, 23}, {112, 73}, {224, 236}, {221, 127}, {167, 12}, {83, 111}, {166, 246}, {81, 108}, {162, 161}, {89, 59}, {178, 82}, {121, 41}, {242, 157}, {249, 85}, {239, 170}, {195, 251}, {155, 96}, {43, 134}, {86, 177}, {172, 187}, {69, 204}, {138, 62}, {9, 90}, {18, 203}, {36, 89}, {72, 95}, {144, 176}, {61, 156}, {122, 169}, {244, 160}, {245, 81}, {247, 11}, {243, 245}, {251, 22}, {235, 235}, {203, 122}, {139, 117}, {11, 44}, {22, 215}, {44, 79}, {88, 174}, {176, 213}, {125, 233}, {250, 230}, {233, 231}, {207, 173}, {131, 232}, {27, 116}, {54, 214}, {108, 244}, {216, 234}, {173, 168}, {71, 80}, {142, 88}, {1, 175}};

const int pattern_count[] = {0, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7};

static void clear_buffer(struct buffer_t *const buf)
{
    buf->bit_index = 0;
    buf->byte_index = 0;
    memset(buf->data, 0, buf->size);
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

static void input_parsing(void **state)
{
    const char *const numeric_input = "1234567890";
    size_t capacity = 2;
    size_t size = 0;
    struct encoding_run_t *run_ptr = malloc(capacity * sizeof(struct encoding_run_t));
    parse_input(numeric_input, &run_ptr, &capacity, &size);
    assert_int_equal(capacity, 2);
    assert_int_equal(size, 1);
    assert_int_equal(run_ptr[0].type, NUMERIC_DATA);
    assert_int_equal(run_ptr[0].char_count, 10);
    free(run_ptr);

    capacity = 2;
    run_ptr = malloc(capacity * sizeof(struct encoding_run_t));
    size = 0;
    const char *const alpha_input = "ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    parse_input(alpha_input, &run_ptr, &capacity, &size);
    assert_int_equal(capacity, 2);
    assert_int_equal(size, 1);
    assert_int_equal(run_ptr[0].type, ALPHANUMERIC_DATA);
    assert_int_equal(run_ptr[0].char_count, 35);
    free(run_ptr);

    capacity = 2;
    run_ptr = malloc(capacity * sizeof(struct encoding_run_t));
    size = 0;
    const char mixed_input[10] = {'A', 'B', 'C', '1', 'a', 0x93U, 0x5FU, 0xEBU, 0xBFU, '\0'};
    parse_input(mixed_input, &run_ptr, &capacity, &size);
    assert_int_equal(capacity, 8);
    assert_int_equal(size, 4);
    assert_int_equal(run_ptr[0].type, ALPHANUMERIC_DATA);
    assert_int_equal(run_ptr[0].char_count, 3);
    assert_int_equal(run_ptr[1].type, NUMERIC_DATA);
    assert_int_equal(run_ptr[1].char_count, 1);
    assert_int_equal(run_ptr[2].type, BYTE_DATA);
    assert_int_equal(run_ptr[2].char_count, 1);
    assert_int_equal(run_ptr[3].type, KANJI_DATA);
    assert_int_equal(run_ptr[3].char_count, 2);
    free(run_ptr);
}

static void input_optimisation(void **state)
{
    int index;
    index = min_micro_qr_version(NUMERIC_MASK, CORRECTION_LEVEL_AUTO);
    assert_int_equal(index, 0);
    index = min_micro_qr_version(NUMERIC_MASK, CORRECTION_LEVEL_L);
    assert_int_equal(index, 1);
    index = min_micro_qr_version(NUMERIC_MASK, CORRECTION_LEVEL_M);
    assert_int_equal(index, 1);
    index = min_micro_qr_version(NUMERIC_MASK, CORRECTION_LEVEL_Q);
    assert_int_equal(index, 3);
    index = min_micro_qr_version(NUMERIC_MASK, CORRECTION_LEVEL_H);
    assert_int_equal(index, 4);

    index = min_micro_qr_version(ALPHANUMERIC_MASK, CORRECTION_LEVEL_AUTO);
    assert_int_equal(index, 1);
    index = min_micro_qr_version(KANJI_MASK, CORRECTION_LEVEL_AUTO);
    assert_int_equal(index, 2);
    index = min_micro_qr_version(BYTE_MASK, CORRECTION_LEVEL_AUTO);
    assert_int_equal(index, 2);
    index = min_micro_qr_version(NUMERIC_MASK | ALPHANUMERIC_MASK, CORRECTION_LEVEL_AUTO);
    assert_int_equal(index, 1);
    index = min_micro_qr_version(NUMERIC_MASK | ALPHANUMERIC_MASK | KANJI_MASK, CORRECTION_LEVEL_AUTO);
    assert_int_equal(index, 2);
    index = min_micro_qr_version(NUMERIC_MASK | ALPHANUMERIC_MASK | BYTE_MASK, CORRECTION_LEVEL_AUTO);
    assert_int_equal(index, 2);
    index = min_micro_qr_version(NUMERIC_MASK | ALPHANUMERIC_MASK | KANJI_MASK | BYTE_MASK, CORRECTION_LEVEL_AUTO);
    assert_int_equal(index, 2);

    int h;
    int module_count = 0;
    {
        struct encoding_run_t test_data[] = {
            {ALPHANUMERIC_DATA, 1},
            {NUMERIC_DATA, 3},
            {NUMERIC_DATA, 0}};
        size_t test_size = 2;
        h = optimise_input(1, CORRECTION_LEVEL_L, test_data, &test_size, &module_count);
        assert_int_equal(test_data[0].type, ALPHANUMERIC_DATA);
        assert_int_equal(test_data[0].char_count, 1);
        assert_int_equal(test_data[1].type, NUMERIC_DATA);
        assert_int_equal(test_data[1].char_count, 3);
        assert_int_equal(module_count, 25);
        assert_int_equal(test_size, 2);
        assert_int_equal(h, 1);
        test_data[1].char_count = 2;
        h = optimise_input(1, CORRECTION_LEVEL_L, test_data, &test_size, &module_count);
        assert_int_equal(test_data[0].type, ALPHANUMERIC_DATA);
        assert_int_equal(test_data[0].char_count, 3);
        assert_int_equal(module_count, 21);
        assert_int_equal(test_size, 1);
        assert_int_equal(h, 1);
    }
    {
        struct encoding_run_t test_data[] = {
            {NUMERIC_DATA, 3},
            {ALPHANUMERIC_DATA, 1},
            {ALPHANUMERIC_DATA, 0}};
        size_t test_size = 2;
        h = optimise_input(1, CORRECTION_LEVEL_L, test_data, &test_size, &module_count);
        assert_int_equal(test_data[0].type, NUMERIC_DATA);
        assert_int_equal(test_data[0].char_count, 3);
        assert_int_equal(test_data[1].type, ALPHANUMERIC_DATA);
        assert_int_equal(test_data[1].char_count, 1);
        assert_int_equal(module_count, 25);
        assert_int_equal(test_size, 2);
        assert_int_equal(h, 1);
        test_data[0].char_count = 2;
        h = optimise_input(1, CORRECTION_LEVEL_L, test_data, &test_size, &module_count);
        assert_int_equal(test_data[0].type, ALPHANUMERIC_DATA);
        assert_int_equal(test_data[0].char_count, 3);
        assert_int_equal(module_count, 21);
        assert_int_equal(test_size, 1);
        assert_int_equal(h, 1);
    }
    {
        struct encoding_run_t test_data[] = {
            {ALPHANUMERIC_DATA, 1},
            {NUMERIC_DATA, 7},
            {ALPHANUMERIC_DATA, 1},
            {ALPHANUMERIC_DATA, 0}};
        size_t test_size = 3;
        h = optimise_input(1, CORRECTION_LEVEL_L, test_data, &test_size, &module_count);
        assert_int_equal(test_data[0].type, ALPHANUMERIC_DATA);
        assert_int_equal(test_data[0].char_count, 1);
        assert_int_equal(test_data[1].type, NUMERIC_DATA);
        assert_int_equal(test_data[1].char_count, 7);
        assert_int_equal(test_data[2].type, ALPHANUMERIC_DATA);
        assert_int_equal(test_data[2].char_count, 1);
        assert_int_equal(module_count, 55);
        assert_int_equal(test_size, 3);
        assert_int_equal(h, 2);
        test_data[1].char_count = 6;
        h = optimise_input(1, CORRECTION_LEVEL_L, test_data, &test_size, &module_count);
        assert_int_equal(test_data[0].type, ALPHANUMERIC_DATA);
        assert_int_equal(test_data[0].char_count, 8);
        assert_int_equal(module_count, 50);
        assert_int_equal(test_size, 1);
        assert_int_equal(h, 2);
    }
}

static void input_encoding(void **state)
{
    uint8_t test_buf[1500];
    struct buffer_t buf = {.bit_index = 0, .byte_index = 0, .size = sizeof(test_buf), .data = test_buf};

    struct encoding_run_t encodings[4] = {
        {.type = NUMERIC_DATA, .char_count = 4},
        {.type = ALPHANUMERIC_DATA, .char_count = 3},
        {.type = BYTE_DATA, .char_count = 4},
        {.type = KANJI_DATA, .char_count = 1}};

    const char *const m1_test = {"1234"};
    const char *const m2_test = {"1234ABC"};
    const char all_test[14] = {'1', '2', '3', '4', 'A', 'B', 'C', 't', 'e', 's', 't', 0x93, 0x5F, '\0'};

    int module_count = 17;
    clear_buffer(&buf);
    qr_encode_input(QR_SIZE_MICRO, 0, CORRECTION_LEVEL_L, module_count, m1_test, encodings, 1, &buf);
    uint8_t m1_check[3] = {0x83U, 0xDAU, 0x00U}; // TODO: Padding check
    assert_memory_equal(test_buf, m1_check, 3);

    module_count = 40;
    clear_buffer(&buf);
    qr_encode_input(QR_SIZE_MICRO, 1, CORRECTION_LEVEL_L, module_count, m2_test, encodings, 2, &buf);
    uint8_t m2_check[6] = {0x20U, 0xF6U, 0x96U, 0x73U, 0x4CU, 0x00U}; // TODO: Padding check
    assert_memory_equal(test_buf, m2_check, 6);

    module_count = 100;
    clear_buffer(&buf);
    qr_encode_input(QR_SIZE_MICRO, 2, CORRECTION_LEVEL_L, module_count, all_test, encodings, 4, &buf);
    uint8_t m3_check[13] = {0x08U, 0x3DU, 0xA2U, 0x67U, 0x34U, 0xC9U, 0x1DU, 0x19U, 0x5CU, 0xDDU, 0x32U, 0xD9, 0xF0}; // TODO: Padding check
    assert_memory_equal(test_buf, m3_check, 13);

    module_count = 108;
    clear_buffer(&buf);
    qr_encode_input(QR_SIZE_MICRO, 3, CORRECTION_LEVEL_L, module_count, all_test, encodings, 4, &buf);
    uint8_t m4_check[14] = {0x02U, 0x0FU, 0x68U, 0x46U, 0x73U, 0x4CU, 0x44U, 0x74U, 0x65U, 0x73U, 0x74U, 0x62U, 0xD9U, 0xF0U}; // TODO: Padding check
    assert_memory_equal(test_buf, m4_check, 14);

    module_count = 127;
    clear_buffer(&buf);
    qr_encode_input(QR_SIZE_STANDARD, 0, CORRECTION_LEVEL_L, module_count, all_test, encodings, 4, &buf);
    uint8_t v1_9_check[16] = {0x10U, 0x10U, 0x7BU, 0x42U, 0x01U, 0x9CU, 0xD3U, 0x10U, 0x11U, 0xD1U, 0x95U, 0xCDU, 0xD2U, 0x00U, 0x5BU, 0x3EU};
    assert_memory_equal(test_buf, v1_9_check, 16);

    module_count = 141;
    clear_buffer(&buf);
    qr_encode_input(QR_SIZE_STANDARD, 9, CORRECTION_LEVEL_L, module_count, all_test, encodings, 4, &buf);
    uint8_t v10_26_check[18] = {0x10U, 0x04U, 0x1EU, 0xD0U, 0x80U, 0x19U, 0xCDU, 0x31U, 0x00U, 0x01U, 0x1DU, 0x19U, 0x5CU, 0xDDU, 0x20U, 0x01U, 0x6CU, 0xF8U};
    assert_memory_equal(test_buf, v10_26_check, 18);

    module_count = 147;
    clear_buffer(&buf);
    qr_encode_input(QR_SIZE_STANDARD, 26, CORRECTION_LEVEL_L, module_count, all_test, encodings, 4, &buf);
    uint8_t v27_40_check[19] = {0x10U, 0x01U, 0x07U, 0xB4U, 0x20U, 0x01U, 0x9CU, 0xD3U, 0x10U, 0x00U, 0x11U, 0xD1U, 0x95U, 0xCDU, 0xD2U, 0x00U, 0x05U, 0xB3U, 0xE0U};
    assert_memory_equal(test_buf, v27_40_check, 19);
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

void data_size_calculations(void **state)
{
    int version;
    size_t data;
    size_t error;
    for (int version_lookup_index = 0; version_lookup_index < 4; ++version_lookup_index)
    {
        for (int correction_level = 0; correction_level < 4; ++correction_level)
        {
            enum code_type_t type = compute_data_word_sizes(correction_level, 0, version_lookup_index, &version, &data, &error);
            assert_int_equal(type, QR_SIZE_MICRO);
            assert_int_equal(version, version_lookup_index);
            assert_int_equal(data, (micro_module_capacities[version][correction_level] + 4) >> 3);
            assert_int_equal(error, micro_error_words[version][correction_level]);
        }
    }

    const size_t qr_data_words[40][4] = {
        {16, 19, 9, 13},
        {28, 34, 16, 22},
        {44, 55, 26, 34},
        {64, 80, 36, 48},
        {86, 108, 46, 62},
        {108, 136, 60, 76},
        {124, 156, 66, 88},
        {154, 194, 86, 110},
        {182, 232, 100, 132},
        {216, 274, 122, 154},
        {254, 324, 140, 180},
        {290, 370, 158, 206},
        {334, 428, 180, 244},
        {365, 461, 197, 261},
        {415, 523, 223, 295},
        {453, 589, 253, 325},
        {507, 647, 283, 367},
        {563, 721, 313, 397},
        {627, 795, 341, 445},
        {669, 861, 385, 485},
        {714, 932, 406, 512},
        {782, 1006, 442, 568},
        {860, 1094, 464, 614},
        {914, 1174, 514, 664},
        {1000, 1276, 538, 718},
        {1062, 1370, 596, 754},
        {1128, 1468, 628, 808},
        {1193, 1531, 661, 871},
        {1267, 1631, 701, 911},
        {1373, 1735, 745, 985},
        {1455, 1843, 793, 1033},
        {1541, 1955, 845, 1115},
        {1631, 2071, 901, 1171},
        {1725, 2191, 961, 1231},
        {1812, 2306, 986, 1286},
        {1914, 2434, 1054, 1354},
        {1992, 2566, 1096, 1426},
        {2102, 2702, 1142, 1502},
        {2216, 2812, 1222, 1582},
        {2334, 2956, 1276, 1666}};
    const int data_bits[40][4] = {
        {128, 152, 72, 104},
        {224, 272, 128, 176},
        {352, 440, 208, 272},
        {512, 640, 288, 384},
        {688, 864, 368, 496},
        {864, 1088, 480, 608},
        {992, 1248, 528, 704},
        {1232, 1552, 688, 880},
        {1456, 1856, 800, 1056},
        {1728, 2192, 976, 1232},
        {2032, 2592, 1120, 1440},
        {2320, 2960, 1264, 1648},
        {2672, 3424, 1440, 1952},
        {2920, 3688, 1576, 2088},
        {3320, 4184, 1784, 2360},
        {3624, 4712, 2024, 2600},
        {4056, 5176, 2264, 2936},
        {4504, 5768, 2504, 3176},
        {5016, 6360, 2728, 3560},
        {5352, 6888, 3080, 3880},
        {5712, 7456, 3248, 4096},
        {6256, 8048, 3536, 4544},
        {6880, 8752, 3712, 4912},
        {7312, 9392, 4112, 5312},
        {8000, 10208, 4304, 5744},
        {8496, 10960, 4768, 6032},
        {9024, 11744, 5024, 6464},
        {9544, 12248, 5288, 6968},
        {10136, 13048, 5608, 7288},
        {10984, 13880, 5960, 7880},
        {11640, 14744, 6344, 8264},
        {12328, 15640, 6760, 8920},
        {13048, 16568, 7208, 9368},
        {13800, 17528, 7688, 9848},
        {14496, 18448, 7888, 10288},
        {15312, 19472, 8432, 10832},
        {15936, 20528, 8768, 11408},
        {16816, 21616, 9136, 12016},
        {17728, 22496, 9776, 12656},
        {18672, 23648, 10208, 13328}};
    for (int v = 0; v < 40; ++v)
    {
        for (int correction_level = 0; correction_level < 4; ++correction_level)
        {
            int version_lookup_index = 4;
            if (v >= 9)
            {
                version_lookup_index = 5;
            }
            if (v >= 26)
            {
                version_lookup_index = 6;
            }
            enum code_type_t type = compute_data_word_sizes(correction_level, data_bits[v][correction_level], version_lookup_index, &version, &data, &error);
            assert_int_equal(type, QR_SIZE_STANDARD);
            assert_int_equal(version, v);
            assert_int_equal(data, qr_data_words[v][correction_level]);
            const int *const blocks = error_blocks[version][correction_level];
            assert_int_equal(error, blocks[0] * (blocks[1] + blocks[3]));
        }
    }
}

void parameter_checks(void **state)
{
    const char *const input = "12345";
    enum encoding_status_t result;
    struct qr_data_t *qr_code = NULL;

    // Out of range inputs
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_AUTO, -1, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_VERSION_SPECIFIED);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_AUTO, 41, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_VERSION_SPECIFIED);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_AUTO, -1, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_CORRECTION_LEVEL_SPECIFIED);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_AUTO, 5, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_CORRECTION_LEVEL_SPECIFIED);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_AUTO, 23, input, &qr_code);
    assert_int_equal(result, QR_ENC_VERSION_REQUIRES_QR_TYPE);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_AUTO, -1, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_VERSION_SPECIFIED);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_AUTO, 5, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_VERSION_SPECIFIED);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_STANDARD, CORRECTION_LEVEL_AUTO, -1, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_VERSION_SPECIFIED);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_STANDARD, CORRECTION_LEVEL_AUTO, 41, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_VERSION_SPECIFIED);
    assert_null(qr_code);

    // Invalid MicroQR correction levels:
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_L, 1, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_M, 1, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_Q, 1, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_H, 1, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_Q, 2, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_H, 2, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_Q, 3, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_H, 3, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_H, 4, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_H, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_INVALID_MICRO_QR_CORRECTION_LEVEL);
    assert_null(qr_code);

    const char *const micro2 = "ABCDE";
    const char *const micro3 = "abcde";
    const char *const micro4 = "abcdefghijklm";

    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_AUTO, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 1);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_NONE);
    assert_int_equal(qr_code->width, 11);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_AUTO, VERSION_AUTO, micro2, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 2);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 13);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_AUTO, VERSION_AUTO, micro3, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 3);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 15);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_AUTO, VERSION_AUTO, micro4, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 4);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 17);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 2);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_L);
    assert_int_equal(qr_code->width, 13);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 2);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 13);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 4);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_Q);
    assert_int_equal(qr_code->width, 17);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 1);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_H);
    assert_int_equal(qr_code->width, 21);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_AUTO, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 1);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_NONE);
    assert_int_equal(qr_code->width, 11);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_L, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 2);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_L);
    assert_int_equal(qr_code->width, 13);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_M, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 2);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 13);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_Q, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 4);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_Q);
    assert_int_equal(qr_code->width, 17);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_MICRO, CORRECTION_LEVEL_AUTO, 3, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_MICRO);
    assert_int_equal(qr_code->version, 3);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 15);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_STANDARD, CORRECTION_LEVEL_AUTO, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 1);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 21);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_STANDARD, CORRECTION_LEVEL_L, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 1);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_L);
    assert_int_equal(qr_code->width, 21);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_STANDARD, CORRECTION_LEVEL_M, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 1);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 21);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_STANDARD, CORRECTION_LEVEL_Q, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 1);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_Q);
    assert_int_equal(qr_code->width, 21);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_STANDARD, CORRECTION_LEVEL_H, VERSION_AUTO, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 1);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_H);
    assert_int_equal(qr_code->width, 21);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_STANDARD, CORRECTION_LEVEL_AUTO, 3, input, &qr_code);
    assert_int_equal(result, QR_ENC_NO_ERROR);
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 3);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 29);
    free(qr_code);
    qr_code = NULL;

    const char test_data[2955] =
        "+Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse sem eros, feugiat sit amet dignissim ut, gravida eu massa. Nunc sed ex ante. Phasellus quis lacus vitae justo ullamcorper accumsan. Morbi efficitur tempor metus, sed sodales massa placerat sit amet. Cras mattis erat porta nibh tempus tristique. Nullam sollicitudin dolor rhoncus, dignissim metus at, semper ante. Nulla malesuada faucibus metus, ac interdum purus euismod at. Nulla tincidunt pretium lacus quis bibendum. Sed risus ante, sollicitudin in vestibulum in, rutrum eget felis."
        "Fusce sollicitudin venenatis felis, eu eleifend lacus tincidunt vel. Sed ac laoreet dolor, eget gravida lectus. Fusce sit amet nunc quis risus tempus semper. Nam eros ligula, aliquet nec risus eu, convallis imperdiet massa. Duis turpis dolor, dictum sit amet eros at, accumsan luctus nisl. Cras libero justo, hendrerit a commodo sed, porta in velit. Nunc id egestas massa, vitae tincidunt tortor. Ut fringilla viverra quam et sollicitudin. Etiam ultrices viverra purus ac egestas. Fusce justo dolor, volutpat nec urna et, congue dapibus lorem. Donec placerat dolor nec quam lobortis, non vestibulum ante aliquam. Vestibulum tincidunt placerat ex sed consequat. Pellentesque at varius magna. Nulla sit amet velit eget ligula vulputate porta."
        "Etiam lobortis turpis ac leo finibus, eu congue turpis venenatis. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vestibulum euismod nisl id mauris vulputate, vel euismod dui mollis. Sed vitae neque commodo, porta ante eget, semper nisl. Sed bibendum congue sollicitudin. Pellentesque tincidunt facilisis est, non elementum sapien sagittis blandit. Etiam quam mauris, euismod sed diam in, aliquam pharetra tellus. Cras vestibulum hendrerit purus non aliquam. Sed consectetur molestie nulla scelerisque bibendum. Aenean laoreet, dui at aliquet semper, ipsum magna bibendum eros, eu tincidunt tortor arcu sit amet sem. Proin nec risus nec ligula sollicitudin scelerisque. Donec pharetra, lacus quis hendrerit tincidunt, neque nulla commodo felis, ac lobortis magna lorem in ex. Proin nec accumsan nunc. Suspendisse venenatis nisi in massa tempor bibendum. Praesent at urna tellus."
        "Morbi purus diam, scelerisque eget nibh volutpat, convallis feugiat est. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Cras ultricies, nisi a placerat lobortis, elit turpis feugiat nibh, a luctus arcu mi quis quam. Aenean lacus mi, fringilla nec risus finibus, tristique hendrerit turpis. Nunc quis justo vehicula dolor convallis facilisis. Fusce commodo nunc mollis tellus dapibus, id fringilla risus aliquam. Sed quis lacus pellentesque, pharetra lectus vel, suscipit turpis. Proin vulputate ultricies elit a molestie. In hac habitasse platea dictumst. Maecenas odio lacus, ultrices nec ligula sit amet, placerat pharetra velit. Aenean ultrices velit non risus viverra faucibus. Mauris ut amet.\0";
    const char *const l_invalid = &test_data[0];
    const char *const l_valid = &test_data[1];
    const char *const m_invalid = &test_data[622];
    const char *const m_valid = &test_data[623];
    const char *const q_invalid = &test_data[1290];
    const char *const q_valid = &test_data[1291];
    const char *const h_invalid = &test_data[1680];
    const char *const h_valid = &test_data[1681];

    char test_data_numeric[7091];
    for (int i = 0; i < 7090; ++i)
    {
        test_data_numeric[i] = rand() % (10) + 48;
    }
    test_data_numeric[7090] = '\0';
    const char *const l_invalid_numeric = &test_data_numeric[0];
    const char *const l_valid_numeric = &test_data_numeric[1];
    const char *const m_invalid_numeric = &test_data_numeric[1493];
    const char *const m_valid_numeric = &test_data_numeric[1494];
    const char *const q_invalid_numeric = &test_data_numeric[3096];
    const char *const q_valid_numeric = &test_data_numeric[3097];
    const char *const h_invalid_numeric = &test_data_numeric[4032];
    const char *const h_valid_numeric = &test_data_numeric[4033];

    char test_data_alphanumeric[4298];
    for (int i = 0; i < 4297; ++i)
    {
        test_data_alphanumeric[i] = rand() % (26) + 'A';
    }
    test_data_alphanumeric[4297] = '\0';
    const char *const l_invalid_alphanumeric = &test_data_alphanumeric[0];
    const char *const l_valid_alphanumeric = &test_data_alphanumeric[1];
    const char *const m_invalid_alphanumeric = &test_data_alphanumeric[905];
    const char *const m_valid_alphanumeric = &test_data_alphanumeric[906];
    const char *const q_invalid_alphanumeric = &test_data_alphanumeric[1876];
    const char *const q_valid_alphanumeric = &test_data_alphanumeric[1877];
    const char *const h_invalid_alphanumeric = &test_data_alphanumeric[2444];
    const char *const h_valid_alphanumeric = &test_data_alphanumeric[2445];

    uint8_t test_data_kanji[3637];
    for (int i = 0; i < 1818 * 2; i += 2)
    {
        test_data_kanji[i] = rand() % (42) + 0x81;
        if (test_data_kanji[i] > 0x9F)
        {
            test_data_kanji[i] += 0x40;
        }
        if (0 == test_data_kanji[i] & 0x01)
        {
            test_data_kanji[i + 1] = rand() % (0x5E) + 0x40;
            if (test_data_kanji[i + 1] > 0x7E)
            {
                ++test_data_kanji[i + 1];
            }
        }
        else
        {
            test_data_kanji[i + 1] = rand() % (0x5E) + 0x9F;
        }
    }
    test_data_kanji[3636] = '\0';
    const char *const l_invalid_kanji = &test_data_kanji[0];
    const char *const l_valid_kanji = &test_data_kanji[2];
    const char *const m_invalid_kanji = &test_data_kanji[764];
    const char *const m_valid_kanji = &test_data_kanji[766];
    const char *const q_invalid_kanji = &test_data_kanji[1586];
    const char *const q_valid_kanji = &test_data_kanji[1588];
    const char *const h_invalid_kanji = &test_data_kanji[2066];
    const char *const h_valid_kanji = &test_data_kanji[2068];

    // Max capacity tests
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, l_invalid, &qr_code);
    assert_null(qr_code);
    time_t start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, l_valid, &qr_code);
    time_t end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_L);
    assert_int_equal(qr_code->width, 177);
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, m_invalid, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, m_valid, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, q_invalid, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, q_valid, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_Q);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, h_invalid, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, h_valid, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_H);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;

    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, l_invalid_numeric, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, l_valid_numeric, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_L);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, m_invalid_numeric, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, m_valid_numeric, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, q_invalid_numeric, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, q_valid_numeric, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_Q);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, h_invalid_numeric, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, h_valid_numeric, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_H);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;

    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, l_invalid_alphanumeric, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, l_valid_alphanumeric, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_L);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, m_invalid_alphanumeric, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, m_valid_alphanumeric, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, q_invalid_alphanumeric, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, q_valid_alphanumeric, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_Q);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, h_invalid_alphanumeric, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, h_valid_alphanumeric, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_H);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;

    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, l_invalid_kanji, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_L, VERSION_AUTO, l_valid_kanji, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_L);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, m_invalid_kanji, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_M, VERSION_AUTO, m_valid_kanji, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_M);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, q_invalid_kanji, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_Q, VERSION_AUTO, q_valid_kanji, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_Q);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, h_invalid_kanji, &qr_code);
    assert_null(qr_code);
    start_time = clock();
    result = qr_encode(QR_SIZE_AUTO, CORRECTION_LEVEL_H, VERSION_AUTO, h_valid_kanji, &qr_code);
    end_time = clock();
    assert_non_null(qr_code);
    assert_int_equal(qr_code->type, QR_SIZE_STANDARD);
    assert_int_equal(qr_code->version, 40);
    assert_int_equal(qr_code->err_level, CORRECTION_LEVEL_H);
    assert_int_equal(qr_code->width, 177);
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    assert_in_range(elapsed_time, 0, 0.015);
    free(qr_code);
    qr_code = NULL;
}

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(input_parsing),
        cmocka_unit_test(input_optimisation),
        cmocka_unit_test(input_encoding),
        cmocka_unit_test(error_code_generation),
        cmocka_unit_test(alignment_positions),
        cmocka_unit_test(data_capacity),
        cmocka_unit_test(image_fill),
        cmocka_unit_test(mask_tests),
        cmocka_unit_test(gf256_lookup_generator),
        cmocka_unit_test(error_polynomial_generator),
        cmocka_unit_test(data_size_calculations),
        cmocka_unit_test(parameter_checks)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
