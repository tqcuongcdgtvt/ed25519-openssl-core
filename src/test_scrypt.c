#include <check.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "scrypt.h"

// Hàm trợ giúp để so sánh hai mảng byte
static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

// Test case cho Hash SHA-256
START_TEST(test_sha256_valid_input) {
    const char *input = "day la du lieu can bam";
    uint8_t output[SHA256_DIGEST_LEN];
    uint8_t expected[SHA256_DIGEST_LEN] = {
        0xba, 0x68, 0x3a, 0xb8, 0x7f, 0xae, 0x6c, 0x41,
        0x23, 0x35, 0x65, 0xb2, 0xf7, 0x66, 0x08, 0x77,
        0xe9, 0x93, 0x99, 0x5d, 0x75, 0x73, 0x49, 0x4f,
        0x50, 0xe6, 0xd2, 0x27, 0xef, 0xd7, 0x35, 0xf1
    };

    int ret = scrypt_hash_sha256((const uint8_t *)input, strlen(input), output);
    ck_assert_int_eq(ret, 0);
    ck_assert(compare_bytes(output, expected, SHA256_DIGEST_LEN));
}
END_TEST

START_TEST(test_sha256_empty_input) {
    const char *input = "";
    uint8_t output[SHA256_DIGEST_LEN];
    uint8_t expected[SHA256_DIGEST_LEN] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    int ret = scrypt_hash_sha256((const uint8_t *)input, 0, output);
    ck_assert_int_eq(ret, 0);
    ck_assert(compare_bytes(output, expected, SHA256_DIGEST_LEN));
}
END_TEST

START_TEST(test_sha256_consistency) {
    const char *input = "test consistency";
    uint8_t output1[SHA256_DIGEST_LEN];
    uint8_t output2[SHA256_DIGEST_LEN];

    int ret1 = scrypt_hash_sha256((const uint8_t *)input, strlen(input), output1);
    int ret2 = scrypt_hash_sha256((const uint8_t *)input, strlen(input), output2);
    ck_assert_int_eq(ret1, 0);
    ck_assert_int_eq(ret2, 0);
    ck_assert(compare_bytes(output1, output2, SHA256_DIGEST_LEN));
}
END_TEST

// Test case cho Ed25519
START_TEST(test_ed25519_generate_keypair) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];

    int ret = scrypt_eddsa_generate_keypair(public_key, private_key);
    ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(test_ed25519_sign_verify_valid) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    const char *message = "test message";

    int ret = scrypt_eddsa_generate_keypair(public_key, private_key);
    ck_assert_int_eq(ret, 0);

    ret = scrypt_eddsa_sign(private_key, (const uint8_t *)message, strlen(message), signature);
    ck_assert_int_eq(ret, 0);

    ret = scrypt_eddsa_verify(public_key, (const uint8_t *)message, strlen(message), signature);
    ck_assert_int_eq(ret, 0);
}
END_TEST

START_TEST(test_ed25519_verify_tampered_message) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    const char *message = "test message";
    const char *tampered_message = "tampered message";

    int ret = scrypt_eddsa_generate_keypair(public_key, private_key);
    ck_assert_int_eq(ret, 0);

    ret = scrypt_eddsa_sign(private_key, (const uint8_t *)message, strlen(message), signature);
    ck_assert_int_eq(ret, 0);

    ret = scrypt_eddsa_verify(public_key, (const uint8_t *)tampered_message, strlen(tampered_message), signature);
    ck_assert_int_eq(ret, 1);
}
END_TEST

START_TEST(test_ed25519_verify_wrong_public_key) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t wrong_public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    const char *message = "test message";

    int ret = scrypt_eddsa_generate_keypair(public_key, private_key);
    ck_assert_int_eq(ret, 0);

    ret = scrypt_eddsa_sign(private_key, (const uint8_t *)message, strlen(message), signature);
    ck_assert_int_eq(ret, 0);

    memset(wrong_public_key, 0, ED25519_PUBLIC_KEY_LEN);
    ret = scrypt_eddsa_verify(wrong_public_key, (const uint8_t *)message, strlen(message), signature);
    ck_assert_int_eq(ret, 1);
}
END_TEST

START_TEST(test_ed25519_verify_wrong_signature) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t wrong_signature[ED25519_SIGNATURE_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    const char *message = "test message";

    int ret = scrypt_eddsa_generate_keypair(public_key, private_key);
    ck_assert_int_eq(ret, 0);

    ret = scrypt_eddsa_sign(private_key, (const uint8_t *)message, strlen(message), signature);
    ck_assert_int_eq(ret, 0);

    memset(wrong_signature, 0, ED25519_SIGNATURE_LEN);
    ret = scrypt_eddsa_verify(public_key, (const uint8_t *)message, strlen(message), wrong_signature);
    ck_assert_int_eq(ret, 1);
}
END_TEST

START_TEST(test_ed25519_verify_empty_message) {
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    const char *message = "test message";
    const char *empty_message = "";

    int ret = scrypt_eddsa_generate_keypair(public_key, private_key);
    ck_assert_int_eq(ret, 0);

    ret = scrypt_eddsa_sign(private_key, (const uint8_t *)message, strlen(message), signature);
    ck_assert_int_eq(ret, 0);

    ret = scrypt_eddsa_verify(public_key, (const uint8_t *)empty_message, 0, signature);
    ck_assert_int_eq(ret, 1);
}
END_TEST

// Suite cho Hash SHA-256
Suite *sha256_suite(void) {
    Suite *s = suite_create("SHA256");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_sha256_valid_input);
    tcase_add_test(tc_core, test_sha256_empty_input);
    tcase_add_test(tc_core, test_sha256_consistency);

    suite_add_tcase(s, tc_core);
    return s;
}

// Suite cho Ed25519
Suite *eddsa_suite(void) {
    Suite *s = suite_create("Ed25519");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ed25519_generate_keypair);
    tcase_add_test(tc_core, test_ed25519_sign_verify_valid);
    tcase_add_test(tc_core, test_ed25519_verify_tampered_message);
    tcase_add_test(tc_core, test_ed25519_verify_wrong_public_key);
    tcase_add_test(tc_core, test_ed25519_verify_wrong_signature);
    tcase_add_test(tc_core, test_ed25519_verify_empty_message);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    SRunner *sr = srunner_create(sha256_suite());
    srunner_add_suite(sr, eddsa_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
