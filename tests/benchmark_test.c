#include <check.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h> // Để dùng getpid() nếu cần
#include "scrypt.h"

#define NUM_THREADS 10
#define ITERATIONS_PER_THREAD 1000

typedef struct {
    int thread_id;
    int failures;
    double total_sign_time; // Thời gian tổng cho ký trong luồng này
} thread_data_t;

void* thread_function(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    const char* message = "test benchmark";
    size_t msg_len = strlen(message);

    data->failures = 0;
    data->total_sign_time = 0.0;

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
        uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
        uint8_t signature[ED25519_SIGNATURE_LEN];

        if (scrypt_eddsa_generate_keypair(public_key, private_key) != 0) {
            data->failures++;
            continue;
        }

        // Đo thời gian ký
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (scrypt_eddsa_sign(private_key, (const uint8_t*)message, msg_len, signature) != 0) {
            data->failures++;
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        data->total_sign_time += (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        int ret = scrypt_eddsa_verify(public_key, (const uint8_t*)message, msg_len, signature);
        if (ret != 0) {
            data->failures++;
        }
    }

    return NULL;
}

START_TEST(test_benchmark) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS] = {0};
    int total_failures = 0;
    double total_sign_time = 0.0;
    double total_time = 0.0;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    printf("Starting benchmark test with %d threads, %d iterations each...\n", NUM_THREADS, ITERATIONS_PER_THREAD);

    // Tạo các luồng
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].failures = 0;
        thread_data[i].total_sign_time = 0.0;
        if (pthread_create(&threads[i], NULL, thread_function, &thread_data[i]) != 0) {
            ck_abort_msg("Failed to create thread %d", i);
        }
    }

    // Chờ các luồng hoàn thành
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total_failures += thread_data[i].failures;
        total_sign_time += thread_data[i].total_sign_time;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    total_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Benchmark test completed. Total failures: %d\n", total_failures);
    printf("Total time: %.4f seconds\n", total_time);
    printf("Average time per sign: %.10f seconds\n", total_sign_time / (NUM_THREADS * ITERATIONS_PER_THREAD));
    printf("Errors per second: %.4f\n", (double)total_failures / total_time);

    ck_assert_int_eq(total_failures, 0); // Không có lỗi nào
}
END_TEST

Suite *benchmark_suite(void) {
    Suite *s = suite_create("Benchmark Test");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_benchmark);
    tcase_set_timeout(tc_core, 300); // Timeout 300 giây

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    SRunner *sr = srunner_create(benchmark_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    if (number_failed == 0) {
        printf("Benchmark test passed!\n");
    } else {
        printf("Benchmark test failed!\n");
    }

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}