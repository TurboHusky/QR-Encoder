#ifndef QR_ENCODER
#define QR_ENCODER

#include <stdint.h>

#define VERSION_AUTO 0

enum code_type_t
{
    QR_SIZE_STANDARD,
    QR_SIZE_MICRO,
    QR_SIZE_AUTO
};

enum error_correction_level_t
{
    CORRECTION_LEVEL_L = 0x01, //  7%
    CORRECTION_LEVEL_M = 0x00, // 15%
    CORRECTION_LEVEL_Q = 0x03, // 25%
    CORRECTION_LEVEL_H = 0x02, // 30%
    CORRECTION_LEVEL_AUTO = 0x04,
    CORRECTION_LEVEL_NONE = 0x05
};

struct qr_data_t
{
    enum code_type_t type;
    enum error_correction_level_t err_level;
    int version;
    int width;
    int mask;
    uint8_t *data;
};

struct qr_data_t *qr_encode(enum code_type_t code_type, const enum error_correction_level_t correction_level, const int qr_version, const char *const data);
#endif
