#include <check.h>
#include <stdlib.h>
#include "scrypt.h"

// Khai báo hàm openssl_eddsa_verify (nếu không có header riêng)
extern int openssl_eddsa_verify(const uint8_t *public_key, const uint8_t *message, size_t message_len, const uint8_t *signature);

START_TEST(test_verify_invalid_public_key_length) {
    unsigned char public_key[31] = {0}; // 31 bytes, không hợp lệ
    unsigned char signature[64] = {0};
    unsigned char message[10] = {0};
    size_t msg_len = 10;
    ck_assert_int_eq(scrypt_eddsa_verify(public_key, message, msg_len, signature), 1);
}
END_TEST

START_TEST(test_verify_invalid_signature_length) {
    unsigned char public_key[32] = {0};
    unsigned char signature[63] = {0}; // 63 bytes, không hợp lệ
    unsigned char message[10] = {0};
    size_t msg_len = 10;
    ck_assert_int_eq(scrypt_eddsa_verify(public_key, message, msg_len, signature), 1);
}
END_TEST

START_TEST(test_verify_valid_data) {
    unsigned char public_key[ED25519_PUBLIC_KEY_LEN];
    unsigned char private_key[ED25519_PRIVATE_KEY_LEN];
    unsigned char signature[ED25519_SIGNATURE_LEN];
    unsigned char message[10] = {0xCC};
    size_t msg_len = 10;

    ck_assert_int_eq(scrypt_eddsa_generate_keypair(public_key, private_key), 0);
    ck_assert_int_eq(scrypt_eddsa_sign(private_key, message, msg_len, signature), 0);
    ck_assert_int_eq(scrypt_eddsa_verify(public_key, message, msg_len, signature), 0);
}
END_TEST

START_TEST(test_verify_null_public_key) {
    unsigned char signature[64] = {0};
    unsigned char message[10] = {0};
    size_t msg_len = 10;
    ck_assert_int_eq(scrypt_eddsa_verify(NULL, message, msg_len, signature), -1);
}
END_TEST

START_TEST(test_verify_null_signature) {
    unsigned char public_key[32] = {0};
    unsigned char message[10] = {0};
    size_t msg_len = 10;
    ck_assert_int_eq(scrypt_eddsa_verify(public_key, message, msg_len, NULL), -1);
}
END_TEST

START_TEST(test_verify_null_message) {
    unsigned char public_key[32] = {0};
    unsigned char signature[64] = {0};
    size_t msg_len = 0; // Để kiểm tra null message
    ck_assert_int_eq(scrypt_eddsa_verify(public_key, NULL, msg_len, signature), -1);
}
END_TEST

START_TEST(test_verify_invalid_signature) {
    unsigned char public_key[ED25519_PUBLIC_KEY_LEN];
    unsigned char private_key[ED25519_PRIVATE_KEY_LEN];
    unsigned char signature[ED25519_SIGNATURE_LEN] = {0}; // Chữ ký không hợp lệ
    unsigned char message[10] = {0xCC};
    size_t msg_len = 10;

    ck_assert_int_eq(scrypt_eddsa_generate_keypair(public_key, private_key), 0);
    ck_assert_int_eq(scrypt_eddsa_sign(private_key, message, msg_len, signature), 0);
    // Thay đổi một byte trong signature để làm không hợp lệ
    signature[0] ^= 0xFF;
    ck_assert_int_eq(scrypt_eddsa_verify(public_key, message, msg_len, signature), 1);
}
END_TEST

START_TEST(test_verify_zero_length_message) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    size_t msg_len = 0;

    // Tạo cặp khóa (giả sử có hàm tạo khóa)
    ck_assert_int_eq(scrypt_eddsa_generate_keypair(public_key, private_key), 0);

    // Sử dụng openssl_eddsa_verify trực tiếp
    uint8_t empty_message[1] = {0}; // Mảng byte rỗng
    int ret = openssl_eddsa_verify(public_key, empty_message, msg_len, signature);
    ck_assert_int_eq(ret, 1); // Mong đợi invalid
}
END_TEST

START_TEST(test_generate_keypair_null_buffer) {
    ck_assert_int_eq(scrypt_eddsa_generate_keypair(NULL, NULL), -1);
}
END_TEST

START_TEST(test_sign_null_private_key) {
    unsigned char signature[ED25519_SIGNATURE_LEN];
    unsigned char message[10] = {0};
    size_t msg_len = 10;
    ck_assert_int_eq(scrypt_eddsa_sign(NULL, message, msg_len, signature), -1);
}
END_TEST

START_TEST(test_sign_null_message) {
    unsigned char private_key[ED25519_PRIVATE_KEY_LEN];
    unsigned char signature[ED25519_SIGNATURE_LEN];
    size_t msg_len = 0;
    ck_assert_int_eq(scrypt_eddsa_generate_keypair(NULL, private_key), -1); // Generate với public key null
    ck_assert_int_eq(scrypt_eddsa_sign(private_key, NULL, msg_len, signature), -1);
}
END_TEST

Suite *boundary_suite(void) {
    Suite *s = suite_create("Boundary Tests");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_verify_invalid_public_key_length);
    tcase_add_test(tc_core, test_verify_invalid_signature_length);
    tcase_add_test(tc_core, test_verify_valid_data);
    tcase_add_test(tc_core, test_verify_null_public_key);
    tcase_add_test(tc_core, test_verify_null_signature);
    tcase_add_test(tc_core, test_verify_null_message);
    tcase_add_test(tc_core, test_verify_invalid_signature);
    tcase_add_test(tc_core, test_verify_zero_length_message);
    tcase_add_test(tc_core, test_generate_keypair_null_buffer);
    tcase_add_test(tc_core, test_sign_null_private_key);
    tcase_add_test(tc_core, test_sign_null_message);
    suite_add_tcase(s, tc_core);
    return s;
}

// Hàm tạo message với độ dài tùy chỉnh
static uint8_t *create_message(size_t len) {
    uint8_t *msg = (uint8_t *)malloc(len);
    if (msg) memset(msg, 0xCC, len); // Điền giá trị mặc định
    return msg;
}

START_TEST(test_verify_max_length_message) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    size_t msg_len = 1024;
    uint8_t *message = create_message(msg_len);

    ck_assert_int_eq(scrypt_eddsa_generate_keypair(public_key, private_key), 0);
    // Giả sử ký với message rỗng trước, rồi kiểm tra verify
    int ret = scrypt_eddsa_verify(public_key, message, msg_len, signature);
    ck_assert_int_eq(ret, 0); // Mong đợi valid (nếu ký hợp lệ)
    free(message);
}
END_TEST

START_TEST(test_verify_below_max_length_message) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    size_t msg_len = 1023;
    uint8_t *message = create_message(msg_len);

    ck_assert_int_eq(scrypt_eddsa_generate_keypair(public_key, private_key), 0);
    int ret = scrypt_eddsa_verify(public_key, message, msg_len, signature);
    ck_assert_int_eq(ret, 0); // Mong đợi valid
    free(message);
}
END_TEST

START_TEST(test_verify_above_max_length_message) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    size_t msg_len = 1025;
    uint8_t *message = create_message(msg_len);

    ck_assert_int_eq(scrypt_eddsa_generate_keypair(public_key, private_key), 0);
    int ret = scrypt_eddsa_verify(public_key, message, msg_len, signature);
    ck_assert_int_eq(ret, -1); // Mong đợi error do vượt 1024
    free(message);
}
END_TEST

int main(void) {
    int number_failed;
    Suite *s = boundary_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}