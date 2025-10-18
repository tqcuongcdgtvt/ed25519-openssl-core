#ifndef SCRYPT_H
#define SCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define SCRYPT_VERSION "1.0.0"
#define SCRYPT_SUCCESS 0
#define SCRYPT_ERROR_INVALID_INPUT -1
#define SCRYPT_ERROR_MEMORY -2
#define SCRYPT_ERROR_VERIFY_FAILED 1

// === API Băm Dữ liệu (Hashing) ===
#define SHA256_DIGEST_LEN 32
#define SHA512_DIGEST_LEN 64

// === API Chữ ký số Ed25519 ===
#define ED25519_PUBLIC_KEY_LEN 32
#define ED25519_PRIVATE_KEY_LEN 32 // Seed 32-byte cho khóa riêng
#define ED25519_SIGNATURE_LEN 64

// Cấu trúc backend cho các hàm mã hóa
typedef struct {
    int (*hash_sha256)(const uint8_t *input, size_t input_len, uint8_t *output);
    int (*hash_sha512)(const uint8_t *input, size_t input_len, uint8_t *output);
    int (*eddsa_generate_keypair)(uint8_t *public_key, uint8_t *private_key);
    int (*eddsa_sign)(const uint8_t *private_key, const uint8_t *message, size_t message_len, uint8_t *signature);
    int (*eddsa_verify)(const uint8_t *public_key, const uint8_t *message, size_t message_len, const uint8_t *signature);
} crypto_backend_t;

// Hàm lấy backend mã hóa
crypto_backend_t* get_crypto_backend(void);

/**
 * @brief Tính giá trị băm SHA-256 của một thông điệp.
 * @param input Thông điệp cần băm, không được NULL.
 * @param input_len Độ dài của thông điệp.
 * @param output Buffer để lưu kết quả băm (32 bytes), không được NULL.
 * @return SCRYPT_SUCCESS nếu thành công, SCRYPT_ERROR_INVALID_INPUT nếu buffer NULL,
 *         SCRYPT_ERROR_MEMORY nếu cấp phát bộ nhớ thất bại.
 */
int scrypt_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output);

/**
 * @brief Tính giá trị băm SHA-512 của một thông điệp.
 * @param input Thông điệp cần băm, không được NULL.
 * @param input_len Độ dài của thông điệp.
 * @param output Buffer để lưu kết quả băm (64 bytes), không được NULL.
 * @return SCRYPT_SUCCESS nếu thành công, SCRYPT_ERROR_INVALID_INPUT nếu buffer NULL,
 *         SCRYPT_ERROR_MEMORY nếu cấp phát bộ nhớ thất bại.
 */
int scrypt_hash_sha512(const uint8_t *input, size_t input_len, uint8_t *output);

/**
 * @brief Tạo một cặp khóa Ed25519 mới.
 * @param public_key Buffer để lưu public key (32 bytes), không được NULL.
 * @param private_key Buffer để lưu private key (32 bytes, seed), không được NULL.
 * @return SCRYPT_SUCCESS nếu thành công, SCRYPT_ERROR_INVALID_INPUT nếu buffer NULL,
 *         SCRYPT_ERROR_MEMORY nếu cấp phát bộ nhớ thất bại.
 * @example
 * uint8_t pub[32], priv[32];
 * int ret = scrypt_eddsa_generate_keypair(pub, priv);
 * if (ret == SCRYPT_SUCCESS) printf("Key generated!\n");
 */
int scrypt_eddsa_generate_keypair(uint8_t *public_key, uint8_t *private_key);

/**
 * @brief Ký một thông điệp bằng private key Ed25519.
 * @param private_key Private key 32-byte (seed), không được NULL.
 * @param message Thông điệp cần ký, không được NULL.
 * @param message_len Độ dài của thông điệp.
 * @param signature Buffer để lưu chữ ký (64 bytes), không được NULL.
 * @return SCRYPT_SUCCESS nếu thành công, SCRYPT_ERROR_INVALID_INPUT nếu buffer NULL,
 *         SCRYPT_ERROR_MEMORY nếu thất bại.
 */
int scrypt_eddsa_sign(const uint8_t *private_key, const uint8_t *message, size_t message_len, uint8_t *signature);

/**
 * @brief Xác thực một chữ ký Ed25519.
 * @param public_key Public key 32-byte, không được NULL.
 * @param message Thông điệp đã được ký, không được NULL.
 * @param message_len Độ dài của thông điệp.
 * @param signature Chữ ký 64-byte cần xác thực, không được NULL.
 * @return SCRYPT_SUCCESS nếu chữ ký hợp lệ, SCRYPT_ERROR_VERIFY_FAILED nếu không hợp lệ,
 *         SCRYPT_ERROR_INVALID_INPUT nếu buffer NULL.
 */
int scrypt_eddsa_verify(const uint8_t *public_key, const uint8_t *message, size_t message_len, const uint8_t *signature);

#ifdef __cplusplus
}
#endif

#endif // SCRYPT_H