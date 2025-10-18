#include <check.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "scrypt.h"

#define NUM_THREADS 10
#define ITERATIONS_PER_THREAD 1000

// Cấu trúc để truyền dữ liệu vào luồng
typedef struct {
    int thread_id;
    int failures;
} thread_data_t;

// Hàm thực thi cho mỗi luồng
void* thread_function(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    const char* message = "test thread safety";
    size_t msg_len = strlen(message);

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
        uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
        uint8_t signature[ED25519_SIGNATURE_LEN];

        // Tạo cặp khóa
        if (scrypt_eddsa_generate_keypair(public_key, private_key) != 0) {
            data->failures++;
            continue;
        }

        // Ký message
        if (scrypt_eddsa_sign(private_key, (const uint8_t*)message, msg_len, signature) != 0) {
            data->failures++;
            continue;
        }

        // Xác thực chữ ký
        int ret = scrypt_eddsa_verify(public_key, (const uint8_t*)message, msg_len, signature);
        if (ret != 0) {
            data->failures++;
        }
    }

    return NULL;
}

START_TEST(test_thread_safety) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS] = {0};
    int total_failures = 0;

    printf("Starting thread safety test with %d threads, %d iterations each...\n", NUM_THREADS, ITERATIONS_PER_THREAD);

    // Tạo các luồng
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].failures = 0;
        if (pthread_create(&threads[i], NULL, thread_function, &thread_data[i]) != 0) {
            ck_abort_msg("Failed to create thread %d", i);
        }
    }

    // Chờ các luồng hoàn thành
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total_failures += thread_data[i].failures;
    }

    printf("Thread safety test completed. Total failures: %d\n", total_failures);
    ck_assert_int_eq(total_failures, 0); // Không có lỗi nào
}
END_TEST

Suite *thread_safety_suite(void) {
    Suite *s = suite_create("Thread Safety Test");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_thread_safety);
    tcase_set_timeout(tc_core, 700); // Timeout 300 giây

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    SRunner *sr = srunner_create(thread_safety_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    if (number_failed == 0) {
        printf("Thread safety test passed! Ready for Valgrind.\n");
    } else {
        printf("Thread safety test failed!\n");
    }

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}