#include <stdlib.h>

#include <stdio.h>
#include "qr.h"


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

    struct qr_data_t *qr_code = qr_encode(params.version, params.correction_level, argv[argc - 1]);
    if (qr_code != NULL)
    {
        export_as_ppm(qr_code->width, qr_code->data);
    }

    free(qr_code);
    qr_code = NULL;
}