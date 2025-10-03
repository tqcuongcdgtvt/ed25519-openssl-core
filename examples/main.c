#include <stdio.h>
#include <string.h>
#include "scrypt.h"

// Hàm trợ giúp để in mảng byte dưới dạng hex
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Hàm kiểm tra các test case cho scrypt_eddsa_verify
void test_scrypt_eddsa_verify() {
    printf("--- Test Hàm scrypt_eddsa_verify ---\n");

    // Chuẩn bị dữ liệu
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    uint8_t wrong_public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t wrong_signature[ED25519_SIGNATURE_LEN];
    const char* sign_message = "Thong diep nay can duoc ky va xac thuc";
    const char* tampered_message = "Thong diep nay da bi thay doi!";
    const char* empty_message = "";

    // Tạo cặp khóa
    if (scrypt_eddsa_generate_keypair(public_key, private_key) != 0) {
        printf("[FAIL] Test: Tạo cặp khóa thất bại!\n");
        return;
    }
    printf("Tạo cặp khóa thành công.\n");
    print_hex("Public Key", public_key, ED25519_PUBLIC_KEY_LEN);

    // Ký thông điệp gốc
    if (scrypt_eddsa_sign(private_key, (const uint8_t*)sign_message, strlen(sign_message), signature) != 0) {
        printf("[FAIL] Test: Ký thông điệp thất bại!\n");
        return;
    }
    printf("Ký thông điệp thành công.\n");
    print_hex("Signature", signature, ED25519_SIGNATURE_LEN);

    // Tạo khóa công khai sai (toàn byte 0)
    memset(wrong_public_key, 0, ED25519_PUBLIC_KEY_LEN);

    // Tạo chữ ký sai (toàn byte 0)
    memset(wrong_signature, 0, ED25519_SIGNATURE_LEN);

    // Test case 1: Chữ ký hợp lệ
    printf("\nTest Case 1: Xác thực chữ ký hợp lệ...\n");
    int verify_status = scrypt_eddsa_verify(public_key, (const uint8_t*)sign_message, strlen(sign_message), signature);
    if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [OK] Test case 1 passed.\n");
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ (mã lỗi: %d).\n", verify_status);
        printf("   [FAIL] Test case 1 failed.\n");
    }

    // Test case 2: Chữ ký không hợp lệ (thông điệp giả mạo)
    printf("\nTest Case 2: Xác thực với thông điệp giả mạo...\n");
    printf("   Thông điệp giả mạo: \"%s\"\n", tampered_message);
    verify_status = scrypt_eddsa_verify(public_key, (const uint8_t*)tampered_message, strlen(tampered_message), signature);
    if (verify_status == 1) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n");
        printf("   [OK] Test case 2 passed.\n");
    } else if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [FAIL] Test case 2 failed.\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n", verify_status);
        printf("   [FAIL] Test case 2 failed.\n");
    }

    // Test case 3: Khóa công khai sai
    printf("\nTest Case 3: Xác thực với khóa công khai sai...\n");
    verify_status = scrypt_eddsa_verify(wrong_public_key, (const uint8_t*)sign_message, strlen(sign_message), signature);
    if (verify_status == 1) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n");
        printf("   [OK] Test case 3 passed.\n");
    } else if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [FAIL] Test case 3 failed.\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n", verify_status);
        printf("   [FAIL] Test case 3 failed.\n");
    }

    // Test case 4: Chữ ký sai
    printf("\nTest Case 4: Xác thực với chữ ký sai...\n");
    verify_status = scrypt_eddsa_verify(public_key, (const uint8_t*)sign_message, strlen(sign_message), wrong_signature);
    if (verify_status == 1) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n");
        printf("   [OK] Test case 4 passed.\n");
    } else if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [FAIL] Test case 4 failed.\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n", verify_status);
        printf("   [FAIL] Test case 4 failed.\n");
    }

    // Test case 5: Thông điệp rỗng
    printf("\nTest Case 5: Xác thực với thông điệp rỗng...\n");
    verify_status = scrypt_eddsa_verify(public_key, (const uint8_t*)empty_message, strlen(empty_message), signature);
    if (verify_status == 1) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n");
        printf("   [OK] Test case 5 passed.\n");
    } else if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [FAIL] Test case 5 failed.\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n", verify_status);
        printf("   [FAIL] Test case 5 failed.\n");
    }

    // Test case 6: Khóa công khai rỗng
    printf("\nTest Case 6: Xác thực với khóa công khai rỗng...\n");
    verify_status = scrypt_eddsa_verify(wrong_public_key, (const uint8_t*)sign_message, strlen(sign_message), signature);
    if (verify_status == 1) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n");
        printf("   [OK] Test case 6 passed.\n");
    } else if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [FAIL] Test case 6 failed.\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n", verify_status);
        printf("   [FAIL] Test case 6 failed.\n");
    }

    // Test case 7: Chữ ký rỗng
    printf("\nTest Case 7: Xác thực với chữ ký rỗng...\n");
    verify_status = scrypt_eddsa_verify(public_key, (const uint8_t*)sign_message, strlen(sign_message), wrong_signature);
    if (verify_status == 1) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n");
        printf("   [OK] Test case 7 passed.\n");
    } else if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [FAIL] Test case 7 failed.\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n", verify_status);
        printf("   [FAIL] Test case 7 failed.\n");
    }

    printf("--- Kết thúc kiểm tra scrypt_eddsa_verify ---\n\n");
}

int main() {
    printf("--- Demo Thư viện Mã hóa Scrypt ---\n\n");

    // === 1. Demo API Băm Dữ liệu (Hashing) ===
    printf("--- 1. Test Chức năng Hash SHA-256 ---\n");
    const char* hash_message = "day la du lieu can bam";
    uint8_t hash_output[SHA256_DIGEST_LEN];

    if (scrypt_hash_sha256((const uint8_t*)hash_message, strlen(hash_message), hash_output) == 0) {
        printf("Du lieu goc: %s\n", hash_message);
        print_hex("SHA-256 Hash", hash_output, SHA256_DIGEST_LEN);
        printf("[OK] Hash thành công.\n");
    } else {
        printf("[FAIL] Hash thất bại.\n");
    }
    printf("\n");

    // === 2. Demo API Chữ ký số Ed25519 ===
    printf("--- 2. Test Chu trình Ký và Xác thực Ed25519 ---\n");
    
    // Chuẩn bị dữ liệu
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t signature[ED25519_SIGNATURE_LEN];
    const char* sign_message = "Thong diep nay can duoc ky va xac thuc";

    // a. Tạo cặp khóa
    printf("a. Đang tạo cặp khóa Ed25519...\n");
    if (scrypt_eddsa_generate_keypair(public_key, private_key) != 0) {
        printf("[FAIL] Tạo cặp khóa thất bại!\n");
        return 1;
    }
    print_hex("   Public Key ", public_key, ED25519_PUBLIC_KEY_LEN);
    printf("   [OK] Tạo cặp khóa thành công.\n\n");

    // b. Ký thông điệp
    printf("b. Đang ký thông điệp...\n");
    printf("   Thông điệp: \"%s\"\n", sign_message);
    if (scrypt_eddsa_sign(private_key, (const uint8_t*)sign_message, strlen(sign_message), signature) != 0) {
        printf("[FAIL] Ký thất bại!\n");
        return 1;
    }
    print_hex("   Signature  ", signature, ED25519_SIGNATURE_LEN);
    printf("   [OK] Ký thành công.\n\n");

    // c. Xác thực chữ ký HỢP LỆ
    printf("c. Đang xác thực chữ ký hợp lệ...\n");
    int verify_status = scrypt_eddsa_verify(public_key, (const uint8_t*)sign_message, strlen(sign_message), signature);
    if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [OK] Xác thực đúng.\n\n");
    } else {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n");
        printf("   [FAIL] Xác thực sai (mã lỗi: %d).\n\n", verify_status);
    }

    // d. Xác thực chữ ký KHÔNG HỢP LỆ (thay đổi thông điệp)
    printf("d. Đang xác thực với thông điệp bị thay đổi...\n");
    const char* tampered_message = "Thong diep nay da bi thay doi!";
    printf("   Thông điệp giả mạo: \"%s\"\n", tampered_message);
    verify_status = scrypt_eddsa_verify(public_key, (const uint8_t*)tampered_message, strlen(tampered_message), signature);
    if (verify_status == 1) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ.\n");
        printf("   [OK] Phát hiện giả mạo thành công.\n\n");
    } else if (verify_status == 0) {
        printf("   >>> KẾT QUẢ: CHỮ KÝ HỢP LỆ.\n");
        printf("   [FAIL] Không phát hiện được giả mạo.\n\n");
    } else {
        printf("   >>> LỖI: Mã lỗi %d.\n", verify_status);
        printf("   [FAIL] Xác thực thất bại do lỗi.\n\n");
    }

    // Chạy các test case bổ sung
    test_scrypt_eddsa_verify();

    printf("--- Demo hoàn tất. ---\n");
    return 0;
}