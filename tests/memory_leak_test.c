#include <check.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "scrypt.h"

START_TEST(test_memory_leak_repetition) {
    const int iterations = 10000; // 10,000 lần lặp
    const char *message = "test memory leak";
    size_t msg_len = strlen(message);

    printf("Starting memory leak test with %d iterations...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
        uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
        uint8_t signature[ED25519_SIGNATURE_LEN];

        ck_assert_int_eq(scrypt_eddsa_generate_keypair(public_key, private_key), 0);
        ck_assert_int_eq(scrypt_eddsa_sign(private_key, (const uint8_t *)message, msg_len, signature), 0);
        int ret = scrypt_eddsa_verify(public_key, (const uint8_t *)message, msg_len, signature);
        ck_assert_int_eq(ret, 0); // Mong đợi hợp lệ
    }
    
    printf("Completed %d iterations successfully\n", iterations);
}
END_TEST

Suite *memory_leak_suite(void) {
    Suite *s = suite_create("Memory Leak Test");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_memory_leak_repetition);
    tcase_set_timeout(tc_core, 700); // Tăng lên 120 giây

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    SRunner *sr = srunner_create(memory_leak_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    if (number_failed == 0) {
        printf("Memory leak test passed! Ready for Valgrind.\n");
    } else {
        printf("Memory leak test failed!\n");
    }

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}