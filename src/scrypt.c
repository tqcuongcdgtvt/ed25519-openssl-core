#include "scrypt.h"
#include <stddef.h> // for NULL
#include <stdio.h>  // for printf

// --- Hashing API ---
int scrypt_hash_sha256(const uint8_t* input, size_t input_len, uint8_t* output) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend || !backend->hash_sha256) {
        printf("Debug: Backend hoặc hash_sha256 là NULL\n");
        return -1;
    }
    return backend->hash_sha256(input, input_len, output);
}

int scrypt_hash_sha512(const uint8_t* input, size_t input_len, uint8_t* output) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend || !backend->hash_sha512) {
        printf("Debug: Backend hoặc hash_sha512 là NULL\n");
        return -1;
    }
    return backend->hash_sha512(input, input_len, output);
}

// --- Digital Signature API ---
int scrypt_eddsa_generate_keypair(uint8_t* public_key, uint8_t* private_key) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend || !backend->eddsa_generate_keypair) {
        printf("Debug: Backend hoặc eddsa_generate_keypair là NULL\n");
        return -1;
    }
    return backend->eddsa_generate_keypair(public_key, private_key);
}

int scrypt_eddsa_sign(const uint8_t* private_key, const uint8_t* message, size_t message_len, uint8_t* signature) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend || !backend->eddsa_sign) {
        printf("Debug: Backend hoặc eddsa_sign là NULL\n");
        return -1;
    }
    return backend->eddsa_sign(private_key, message, message_len, signature);
}

int scrypt_eddsa_verify(const uint8_t* public_key, const uint8_t* message, size_t message_len, const uint8_t* signature) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend || !backend->eddsa_verify) {
        printf("Debug: Backend hoặc eddsa_verify là NULL\n");
        return -1;
    }
    printf("Debug: Gọi backend->eddsa_verify\n");
    // In public_key dưới dạng hex
    printf("Debug - Public Key: ");
    for (size_t i = 0; i < ED25519_PUBLIC_KEY_LEN; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");
    // In signature dưới dạng hex
    printf("Debug - Signature: ");
    for (size_t i = 0; i < ED25519_SIGNATURE_LEN; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    // In message dưới dạng byte
    printf("Debug - Message (byte): ");
    for (size_t i = 0; i < message_len; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
    int result = backend->eddsa_verify(public_key, message, message_len, signature);
    printf("Debug: backend->eddsa_verify trả về %d\n", result);
    return result;
}