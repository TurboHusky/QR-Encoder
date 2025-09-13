#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include "qr.h"

#define BAD_VALUE -1

struct user_params_t
{
    int version;
    enum error_correction_level_t correction_level;
    enum code_type_t code_type;
};

int parse_version(const char *const input)
{
    size_t input_size = strlen(input);
    if (1 == input_size && input[0] >= '0' && input[0] <= '9')
    {
        return input[0] - '0';
    }
    else if (2 == input_size && input[0] >= '0' && input[0] <= '4' && input[1] >= '0' && input[1] <= '9')
    {
        return 10 * (input[0] - '0') + input[1] - '0';
    }
    return BAD_VALUE;
}

int parse_qr_input(const int argc, const char *const *const argv, struct user_params_t *user_settings)
{
    user_settings->code_type = QR_SIZE_STANDARD;
    user_settings->version = VERSION_AUTO;
    user_settings->correction_level = CORRECTION_LEVEL_AUTO;

    if (argc < 2)
    {
        printf("No input data provided\n");
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc - 1; ++i)
    {
        size_t arg_size = strlen(argv[i]);
        if ('-' == argv[i][0])
        {
            if (1 == arg_size)
            {
                printf("Invalid argument\n");
                return EXIT_FAILURE;
            }
            if ((3 == arg_size && 0 == strncmp(argv[i], "--h", 3)) || (6 == arg_size && 0 == strncmp(argv[i], "--help", 6)))
            {
                printf("Usage: qr [--auto|--micro] [--version] [-lLmMqQhH] SOURCE\n\n"
                       "\t--h,--help\tPrint help\n"
                       "\t--auto\t\tAllow micro QR codes\n"
                       "\t--micro\t\tGenerate micro QR code\n"
                       "\t--version\tQR version to generate\n"
                       "\t\t\tNot compatible with '--auto' option\n"
                       "\t-l,-L\t\terror correction 7%%\n"
                       "\t-m,-M\t\terror correction 15%%\n"
                       "\t-q,-Q\t\terror correction 25%%\n"
                       "\t-h,-H\t\terror correction 30%%\n");
                return EXIT_FAILURE;
            }
            if (6 == arg_size && 0 == strncmp(argv[i], "--auto", 6))
            {
                user_settings->code_type = QR_SIZE_AUTO;
                continue;
            }
            if (7 == arg_size && 0 == strncmp(argv[i], "--micro", 7))
            {
                user_settings->code_type = QR_SIZE_MICRO;
                continue;
            }
            if (9 == arg_size && 0 == strncmp(argv[i], "--version", 9))
            {
                ++i;
                if (i >= (argc - 1))
                {
                    printf("Missing version argument\n");
                    return EXIT_FAILURE;
                }
                user_settings->version = parse_version(argv[i]);
                if (BAD_VALUE == user_settings->version)
                {
                    printf("Invalid version\n");
                    return EXIT_FAILURE;
                }
                continue;
            }
            switch (argv[i][1])
            {
            case 'l':
            case 'L':
                user_settings->correction_level = CORRECTION_LEVEL_L;
                break;
            case 'm':
            case 'M':
                user_settings->correction_level = CORRECTION_LEVEL_M;
                break;
            case 'q':
            case 'Q':
                user_settings->correction_level = CORRECTION_LEVEL_Q;
                break;
            case 'h':
            case 'H':
                user_settings->correction_level = CORRECTION_LEVEL_H;
                break;
            default:
                printf("Invalid option\n");
                return EXIT_FAILURE;
                break;
            }
        }
        else if (i != (argc - 1))
        {
            printf("Unrecognised input option\n");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

void print_status(enum encoding_status_t status)
{
    switch (status)
    {
    case QR_ENC_NO_ERROR:
        printf("QR code generated successfully\n");
        break;
    case QR_ENC_NO_INPUT_DATA:
        printf("No input data provided\n");
        break;
    case QR_ENC_INVALID_CORRECTION_LEVEL_SPECIFIED:
        printf("Invalid correction level specified\n");
        break;
    case QR_ENC_INVALID_CODE_TYPE_SPECIFIED:
        printf("Invalid code type specified\n");
        break;
    case QR_ENC_INVALID_VERSION_SPECIFIED:
        printf("Invalid version specified\n");
        break;
    case QR_ENC_VERSION_REQUIRES_QR_TYPE:
        printf("QR code type required when specifying version\n");
        break;
    case QR_ENC_INPUT_PARSING_FAILED:
        printf("Input parsing failed\n");
        break;
    case QR_ENC_DATA_EXCEEDS_QR_CAPACITY:
        printf("Input data exceeds capacity for QR code\n");
        break;
    case QR_ENC_DATA_EXCEEDS_MICRO_QR_CAPACITY:
        printf("Input data exceeds capacity for Micro QR code\n");
        break;
    }
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

int main(int argc, char **argv)
{
    struct user_params_t params;
    if (EXIT_FAILURE == parse_qr_input(argc, (const char *const *const)argv, &params))
    {
        return EXIT_FAILURE;
    }
    
    struct qr_data_t *qr_code = NULL;
    enum encoding_status_t status = qr_encode(params.code_type, params.correction_level, params.version, argv[argc - 1], &qr_code);
    print_status(status);
    if (qr_code != NULL)
    {
        export_as_ppm(qr_code->width, qr_code->data);
    }

    free(qr_code);
    qr_code = NULL;
}
