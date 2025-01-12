#ifndef QR_ENCODER
#define QR_ENCODER

#include <stdint.h>

#define VERSION_UNDEFINED -1

enum error_correction_level_t
{
    err_L = 0x01, //  7%
    err_M = 0x00, // 15%
    err_Q = 0x03, // 25%
    err_H = 0x02  // 30%
};

struct user_params_t
{
    int version;
    enum error_correction_level_t correction_level;
};

struct qr_data_t
{
    enum error_correction_level_t err_level;
    int version;
    int width;
    int mask;
    uint8_t *data;
};

int parse_qr_input(const int argc, const char *const *const argv, struct user_params_t *user_settings);
struct qr_data_t *qr_encode(const int qr_version, const enum error_correction_level_t correction_level, const char *const data);
#endif