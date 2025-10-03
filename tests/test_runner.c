// tests/test_runner.c

#include "scrypt.h"
#include <stdio.h>
#include <string.h>

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("--- Bat dau kiem thu Thu vien Ma hoa ---\n\n");
    int result;

    // --- Test Case 1: Tao cap khoa Ed25519 ---
    printf("--- Dang test: scrypt_eddsa_generate_keypair() ---\n");
    uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
    result = scrypt_eddsa_generate_keypair(public_key, private_key);
    if (result != 0) {
        printf(">>> [THAT BAI] Ham generate_keypair tra ve ma loi: %d\n", result);
        return 1;
    }
    printf(">>> [OK] Tao cap khoa thanh cong.\n\n");

    // --- Test Case 2: Ky thong diep Ed25519 ---
    printf("--- Dang test: scrypt_eddsa_sign() ---\n");
    const char* message = "Day la thong diep can duoc ky de kiem tra.";
    uint8_t signature[ED25519_SIGNATURE_LEN];
    result = scrypt_eddsa_sign(private_key, (const uint8_t*)message, strlen(message), signature);
    if (result != 0) {
        printf(">>> [THAT BAI] Ham sign tra ve ma loi: %d\n", result);
        return 1;
    }
    printf(">>> [OK] Ky thong diep thanh cong.\n\n");

    // --- Test Case 3: Xac thuc chu ky HOP LE ---
    printf("--- Dang test: scrypt_eddsa_verify() (hop le) ---\n");
    result = scrypt_eddsa_verify(public_key, (const uint8_t*)message, strlen(message), signature);
    if (result != 0) {
        printf(">>> [THAT BAI] Chu ky hop le bi xac thuc sai!\n");
        return 1;
    }
    printf(">>> [OK] Xac thuc chu ky hop le thanh cong.\n\n");

    // --- Test Case 4: Xac thuc chu ky KHONG HOP LE ---
    printf("--- Dang test: scrypt_eddsa_verify() (khong hop le) ---\n");
    // Cố tình làm hỏng chữ ký
    signature[0] ^= 0xff; 
    result = scrypt_eddsa_verify(public_key, (const uint8_t*)message, strlen(message), signature);
    if (result == 0) { // Lần này, thành công (0) mới là lỗi
        printf(">>> [THAT BAI] Chu ky KHONG hop le lai duoc xac thuc dung!\n");
        return 1;
    }
    printf(">>> [OK] Phat hien chu ky khong hop le thanh cong.\n\n");
    
    printf("--- Tat ca cac bai test Ed25519 da hoan tat! ---\n");
    return 0;
}