#include <stdio.h>
#include <string.h>
#include "scrypt.h"

int main() {
    printf("--- Demo Thư viện Mã hóa Scrypt ---\n\n");

    // 1. Test Chức năng Hash SHA-256
    printf("--- 1. Test Chức năng Hash SHA-256 ---\n");
    const char *hash_input = "day la du lieu can bam";
    unsigned char hash_output[SHA256_DIGEST_LEN];
    if (scrypt_hash_sha256((const unsigned char *)hash_input, strlen(hash_input), hash_output) == 0) {
        printf("Du lieu goc: %s\n", hash_input);
        printf("SHA-256 Hash: ");
        for (int i = 0; i < SHA256_DIGEST_LEN; i++) {
            printf("%02x", hash_output[i]);
        }
        printf("\n[OK] Hash thành công.\n");
    } else {
        printf("[FAIL] Hash thất bại.\n");
    }
    printf("\n");

    // 2. Test Chu trình Ký và Xác thực Ed25519
    printf("--- 2. Test Chu trình Ký và Xác thực Ed25519 ---\n");
    unsigned char public_key[ED25519_PUBLIC_KEY_LEN];
    unsigned char private_key[ED25519_PRIVATE_KEY_LEN];
    unsigned char signature[ED25519_SIGNATURE_LEN];
    const char *message = "Thong diep nay can duoc ky va xac thuc";

    printf("a. Đang tạo cặp khóa Ed25519...\n");
    if (scrypt_eddsa_generate_keypair(public_key, private_key) == 0) {
        printf("   Public Key : ");
        for (int i = 0; i < ED25519_PUBLIC_KEY_LEN; i++) {
            printf("%02x", public_key[i]);
        }
        printf("\n   [OK] Tạo cặp khóa thành công.\n");
    } else {
        printf("   [FAIL] Tạo cặp khóa thất bại.\n");
    }

    printf("b. Đang ký thông điệp...\n");
    if (scrypt_eddsa_sign(private_key, (const unsigned char *)message, strlen(message), signature) == 0) {
        printf("   Thông điệp: \"%s\"\n", message);
        printf("   Signature  : ");
        for (int i = 0; i < ED25519_SIGNATURE_LEN; i++) {
            printf("%02x", signature[i]);
        }
        printf("\n   [OK] Ký thành công.\n");
    } else {
        printf("   [FAIL] Ký thất bại.\n");
    }

    printf("c. Đang xác thực chữ ký hợp lệ...\n");
    int verify_result = scrypt_eddsa_verify(public_key, (const unsigned char *)message, strlen(message), signature);
    printf("Debug: Gọi backend->eddsa_verify\n");
    printf("Debug - Public Key: ");
    for (int i = 0; i < ED25519_PUBLIC_KEY_LEN; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");
    printf("Debug - Signature: ");
    for (int i = 0; i < ED25519_SIGNATURE_LEN; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    printf("Debug - Message (byte): ");
    for (size_t i = 0; i < strlen(message); i++) {
        printf("%02x ", (unsigned char)message[i]);
    }
    printf("\n");
    if (verify_result == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [OK] Xác thực đúng.\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n   [FAIL] Xác thực thất bại.\n", verify_result);
    }

    printf("d. Đang xác thực với thông điệp bị thay đổi...\n");
    const char *fake_message = "Thong diep nay da bi thay doi!";
    verify_result = scrypt_eddsa_verify(public_key, (const unsigned char *)fake_message, strlen(fake_message), signature);
    printf("Debug: Gọi backend->eddsa_verify\n");
    printf("Debug - Public Key: ");
    for (int i = 0; i < ED25519_PUBLIC_KEY_LEN; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");
    printf("Debug - Signature: ");
    for (int i = 0; i < ED25519_SIGNATURE_LEN; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    printf("Debug - Message (byte): ");
    for (size_t i = 0; i < strlen(fake_message); i++) {
        printf("%02x ", (unsigned char)fake_message[i]);
    }
    printf("\n");
    if (verify_result == 1) { // Chấp nhận 1 cho invalid
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n   [OK] Xác thực đúng (thông điệp giả mạo).\n");
    } else if (verify_result == -1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [FAIL] Xác thực thất bại do lỗi.\n", verify_result);
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [FAIL] Xác thực sai (nên thất bại).\n");
    }

    // Test Hàm scrypt_eddsa_verify
    printf("\n--- Test Hàm scrypt_eddsa_verify ---\n");
    unsigned char test_public_key[ED25519_PUBLIC_KEY_LEN];
    unsigned char test_private_key[ED25519_PRIVATE_KEY_LEN];
    unsigned char test_signature[ED25519_SIGNATURE_LEN];
    const char *test_message = "Thong diep nay can duoc ky va xac thuc";

    printf("Tạo cặp khóa thành công.\n");
    if (scrypt_eddsa_generate_keypair(test_public_key, test_private_key) == 0) {
        printf("Public Key: ");
        for (int i = 0; i < ED25519_PUBLIC_KEY_LEN; i++) {
            printf("%02x", test_public_key[i]);
        }
        printf("\n");
    } else {
        printf("[FAIL] Tạo cặp khóa thất bại.\n");
    }

    printf("Ký thông điệp thành công.\n");
    if (scrypt_eddsa_sign(test_private_key, (const unsigned char *)test_message, strlen(test_message), test_signature) == 0) {
        printf("Signature: ");
        for (int i = 0; i < ED25519_SIGNATURE_LEN; i++) {
            printf("%02x", test_signature[i]);
        }
        printf("\n");
    } else {
        printf("[FAIL] Ký thất bại.\n");
    }

    // Test Case 1: Xác thực chữ ký hợp lệ
    printf("Test Case 1: Xác thực chữ ký hợp lệ...\n");
    verify_result = scrypt_eddsa_verify(test_public_key, (const unsigned char *)test_message, strlen(test_message), test_signature);
    if (verify_result == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [OK] Test case 1 passed.\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n   [FAIL] Test case 1 failed.\n", verify_result);
    }

    // Test Case 2: Xác thực với thông điệp giả mạo
    printf("Test Case 2: Xác thực với thông điệp giả mạo...\n");
    const char *test_fake_message = "Thong diep nay da bi thay doi!";
    verify_result = scrypt_eddsa_verify(test_public_key, (const unsigned char *)test_fake_message, strlen(test_fake_message), test_signature);
    if (verify_result == 1) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n   [OK] Test case 2 passed.\n");
    } else if (verify_result == -1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [FAIL] Test case 2 failed.\n", verify_result);
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [FAIL] Test case 2 failed.\n");
    }

    // Test Case 3: Xác thực với khóa công khai sai
    printf("Test Case 3: Xác thực với khóa công khai sai...\n");
    unsigned char wrong_public_key[ED25519_PUBLIC_KEY_LEN] = {0};
    verify_result = scrypt_eddsa_verify(wrong_public_key, (const unsigned char *)test_message, strlen(test_message), test_signature);
    if (verify_result == 1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [OK] Test case 3 passed.\n", verify_result);
    } else if (verify_result == -1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [FAIL] Test case 3 failed.\n", verify_result);
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [FAIL] Test case 3 failed.\n");
    }

    // Test Case 4: Xác thực với chữ ký sai
    printf("Test Case 4: Xác thực với chữ ký sai...\n");
    unsigned char wrong_signature[ED25519_SIGNATURE_LEN] = {0};
    verify_result = scrypt_eddsa_verify(test_public_key, (const unsigned char *)test_message, strlen(test_message), wrong_signature);
    if (verify_result == 1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [OK] Test case 4 passed.\n", verify_result);
    } else if (verify_result == -1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [FAIL] Test case 4 failed.\n", verify_result);
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [FAIL] Test case 4 failed.\n");
    }

    // Test Case 5: Xác thực với thông điệp rỗng
    printf("Test Case 5: Xác thực với thông điệp rỗng...\n");
    verify_result = scrypt_eddsa_verify(test_public_key, NULL, 0, test_signature);
    if (verify_result == -1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [OK] Test case 5 passed.\n", verify_result);
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [FAIL] Test case 5 failed.\n");
    }

    // Test Case 6: Xác thực với khóa công khai rỗng
    printf("Test Case 6: Xác thực với khóa công khai rỗng...\n");
    verify_result = scrypt_eddsa_verify(wrong_public_key, (const unsigned char *)test_message, strlen(test_message), test_signature);
    if (verify_result == 1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [OK] Test case 6 passed.\n", verify_result);
    } else if (verify_result == -1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [FAIL] Test case 6 failed.\n", verify_result);
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [FAIL] Test case 6 failed.\n");
    }

    // Test Case 7: Xác thực với chữ ký rỗng
    printf("Test Case 7: Xác thực với chữ ký rỗng...\n");
    verify_result = scrypt_eddsa_verify(test_public_key, (const unsigned char *)test_message, strlen(test_message), wrong_signature);
    if (verify_result == 1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [OK] Test case 7 passed.\n", verify_result);
    } else if (verify_result == -1) {
        printf("   >>> LỖI: Mã lỗi %d.\n   [FAIL] Test case 7 failed.\n", verify_result);
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n   [FAIL] Test case 7 failed.\n");
    }

    printf("\n--- Kết thúc kiểm tra scrypt_eddsa_verify ---\n\n");
    printf("--- Demo hoàn tất. ---\n");

    return 0;
}