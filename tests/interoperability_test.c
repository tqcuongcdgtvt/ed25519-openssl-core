#include <check.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "scrypt.h"

extern int openssl_eddsa_verify(const uint8_t *public_key, const uint8_t *message, size_t message_len, const uint8_t *signature);

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

START_TEST(test_sha256_interoperability) {
    if (sodium_init() < 0) {
        ck_abort_msg("libsodium initialization failed");
    }

    const char *input = "day la du lieu can bam";
    uint8_t scrypt_output[SHA256_DIGEST_LEN];
    uint8_t sodium_output[SHA256_DIGEST_LEN];

    ck_assert_int_eq(scrypt_hash_sha256((const uint8_t *)input, strlen(input), scrypt_output), 0);
    crypto_hash_sha256(sodium_output, (const uint8_t *)input, strlen(input));

    char scrypt_hex[SHA256_DIGEST_LEN * 2 + 1];
    char sodium_hex[SHA256_DIGEST_LEN * 2 + 1];
    bytes_to_hex(scrypt_output, SHA256_DIGEST_LEN, scrypt_hex);
    bytes_to_hex(sodium_output, SHA256_DIGEST_LEN, sodium_hex);

    printf("SHA-256 from Scrypt: %s\n", scrypt_hex);
    printf("SHA-256 from libsodium: %s\n", sodium_hex);
    ck_assert_mem_eq(scrypt_output, sodium_output, SHA256_DIGEST_LEN);
}
END_TEST

START_TEST(test_ed25519_sign_interoperability) {
    if (sodium_init() < 0) {
        ck_abort_msg("libsodium initialization failed");
    }

    uint8_t scrypt_public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t scrypt_private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t scrypt_signature[ED25519_SIGNATURE_LEN];
    const char *message = "test message";

    ck_assert_int_eq(scrypt_eddsa_generate_keypair(scrypt_public_key, scrypt_private_key), 0);
    ck_assert_int_eq(scrypt_eddsa_sign(scrypt_private_key, (const uint8_t *)message, strlen(message), scrypt_signature), 0);

    char pub_hex[ED25519_PUBLIC_KEY_LEN * 2 + 1];
    char sig_hex[ED25519_SIGNATURE_LEN * 2 + 1];
    bytes_to_hex(scrypt_public_key, ED25519_PUBLIC_KEY_LEN, pub_hex);
    bytes_to_hex(scrypt_signature, ED25519_SIGNATURE_LEN, sig_hex);

    printf("Public Key (hex): %s\n", pub_hex);
    printf("Signature (hex): %s\n", sig_hex);

    // Chuyển seed 32 byte sang private key 64 byte cho libsodium
    uint8_t sodium_private_key[crypto_sign_SECRETKEYBYTES];
    memcpy(sodium_private_key, scrypt_private_key, ED25519_PRIVATE_KEY_LEN); // Seed
    memcpy(sodium_private_key + ED25519_PRIVATE_KEY_LEN, scrypt_public_key, ED25519_PUBLIC_KEY_LEN); // Public key

    // Tạo lại chữ ký bằng libsodium để so sánh
    uint8_t sodium_signature[crypto_sign_BYTES];
    crypto_sign_detached(sodium_signature, NULL, (const uint8_t *)message, strlen(message), sodium_private_key);

    char sodium_sig_hex[crypto_sign_BYTES * 2 + 1];
    bytes_to_hex(sodium_signature, crypto_sign_BYTES, sodium_sig_hex);
    printf("Signature from libsodium: %s\n", sodium_sig_hex);

    // Xác thực bằng libsodium
    if (crypto_sign_verify_detached(scrypt_signature, (const uint8_t *)message, strlen(message), scrypt_public_key) == 0) {
        printf("libsodium verified Scrypt signature successfully\n");
        ck_assert_msg(1, "Verification passed");
    } else {
        ck_abort_msg("libsodium failed to verify Scrypt signature");
    }
}
END_TEST

START_TEST(test_ed25519_verify_interoperability) {
    if (sodium_init() < 0) {
        ck_abort_msg("libsodium initialization failed");
    }

    uint8_t sodium_public_key[crypto_sign_PUBLICKEYBYTES];
    uint8_t sodium_private_key[crypto_sign_SECRETKEYBYTES];
    uint8_t sodium_signature[crypto_sign_BYTES];
    const char *message = "test message";

    // Tạo khóa và ký bằng libsodium
    crypto_sign_keypair(sodium_public_key, sodium_private_key);
    crypto_sign_detached(sodium_signature, NULL, (const uint8_t *)message, strlen(message), sodium_private_key);

    char pub_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    char sig_hex[crypto_sign_BYTES * 2 + 1];
    bytes_to_hex(sodium_public_key, crypto_sign_PUBLICKEYBYTES, pub_hex);
    bytes_to_hex(sodium_signature, crypto_sign_BYTES, sig_hex);

    printf("Public Key from libsodium (hex): %s\n", pub_hex);
    printf("Signature from libsodium (hex): %s\n", sig_hex);

    // Lấy seed 32 byte từ private key libsodium
    uint8_t scrypt_private_key[ED25519_PRIVATE_KEY_LEN];
    memcpy(scrypt_private_key, sodium_private_key, ED25519_PRIVATE_KEY_LEN); // Chỉ dùng seed

    // Xác thực bằng Scrypt
    int ret = scrypt_eddsa_verify(sodium_public_key, (const uint8_t *)message, strlen(message), sodium_signature);
    ck_assert_int_eq(ret, 0); // Mong đợi valid
}
END_TEST

Suite *interoperability_suite(void) {
    Suite *s = suite_create("Interoperability");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_sha256_interoperability);
    tcase_add_test(tc_core, test_ed25519_sign_interoperability);
    tcase_add_test(tc_core, test_ed25519_verify_interoperability);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    SRunner *sr = srunner_create(interoperability_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}