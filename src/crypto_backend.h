// src/crypto_backend.h

#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct crypto_backend_s
 * @brief Một cấu trúc trừu tượng chứa các con trỏ hàm đến các hàm mã hóa của backend.
 *
 * Lớp trừu tượng này cho phép thư viện chính gọi các hàm mã hóa mà không cần biết
 * chi tiết về thư viện nền đang được sử dụng (ví dụ: OpenSSL, wolfSSL).
 */
typedef struct crypto_backend_s {
    /** @name Con trỏ hàm cho Hashing */
    ///@{
    int (*hash_sha256)(const uint8_t *input, size_t input_len, uint8_t *output);
    int (*hash_sha512)(const uint8_t *input, size_t input_len, uint8_t *output);
    ///@}

    /** @name Con trỏ hàm cho Chữ ký số Ed25519 */
    ///@{
    int (*eddsa_generate_keypair)(uint8_t *public_key, uint8_t *private_key);
    int (*eddsa_sign)(const uint8_t *private_key, const uint8_t *message, size_t message_len, uint8_t *signature);
    int (*eddsa_verify)(const uint8_t *public_key, const uint8_t *message, size_t message_len, const uint8_t *signature);
    ///@}
} crypto_backend_t;

/**
 * @brief Lấy con trỏ hằng tới backend mã hóa đang hoạt động.
 *
 * Hàm này trả về một con trỏ tới một cấu trúc backend đã được khởi tạo,
 * chứa các con trỏ hàm đến các triển khai mã hóa cụ thể.
 *
 * @return const crypto_backend_t* Con trỏ tới backend.
 */
const crypto_backend_t* get_crypto_backend(void);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_BACKEND_H