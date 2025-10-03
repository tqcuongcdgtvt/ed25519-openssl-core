#ifndef SCRYPT_H
#define SCRYPT_H

#include <stdint.h> // Cần cho kiểu dữ liệu uint8_t
#include <stddef.h> // Cần cho kiểu dữ liệu size_t

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

// Khai báo (prototype) cho các hàm hash
int scrypt_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output);
int scrypt_hash_sha512(const uint8_t *input, size_t input_len, uint8_t *output);

/**
 * @brief Tạo một cặp khóa Ed25519 mới.
 * @param public_key Buffer để lưu public key (32 bytes).
 * @param private_key Buffer để lưu private key (32 bytes, seed).
 * @return 0 nếu thành công, -1 nếu thất bại.
 */
int scrypt_eddsa_generate_keypair(uint8_t *public_key, uint8_t *private_key);

/**
 * @brief Ký một thông điệp bằng private key Ed25519.
 * @param private_key Private key 32-byte (seed).
 * @param message Thông điệp cần ký.
 * @param message_len Độ dài của thông điệp.
 * @param signature Buffer để lưu chữ ký (64 bytes).
 * @return 0 nếu thành công, -1 nếu thất bại.
 */
int scrypt_eddsa_sign(const uint8_t *private_key, const uint8_t *message, size_t message_len, uint8_t *signature);

/**
 * @brief Xác thực một chữ ký Ed25519.
 * @param public_key Public key 32-byte.
 * @param message Thông điệp đã được ký.
 * @param message_len Độ dài của thông điệp.
 * @param signature Chữ ký 64-byte cần xác thực.
 * @return 0 nếu chữ ký hợp lệ, 1 nếu không hợp lệ, -1 nếu có lỗi.
 */
int scrypt_eddsa_verify(const uint8_t *public_key, const uint8_t *message, size_t message_len, const uint8_t *signature);

#endif // SCRYPT_H