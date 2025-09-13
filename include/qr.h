#ifndef QR_ENCODER
#define QR_ENCODER

#include <stdint.h>

#define VERSION_AUTO 0

enum encoding_status_t
{
    QR_ENC_NO_ERROR,
    QR_ENC_NO_INPUT_DATA,
    QR_ENC_INVALID_CORRECTION_LEVEL_SPECIFIED,
    QR_ENC_INVALID_CODE_TYPE_SPECIFIED,
    QR_ENC_INVALID_VERSION_SPECIFIED,
    QR_ENC_VERSION_REQUIRES_QR_TYPE,
    QR_ENC_INPUT_PARSING_FAILED,
    QR_ENC_DATA_EXCEEDS_QR_CAPACITY,
    QR_ENC_DATA_EXCEEDS_MICRO_QR_CAPACITY
};

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

enum encoding_status_t qr_encode(enum code_type_t code_type, const enum error_correction_level_t correction_level, const int qr_version, const char *const input_data, struct qr_data_t **qr_code);
#endif
