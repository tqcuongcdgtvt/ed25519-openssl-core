#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include "scrypt.h"

int openssl_hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("Debug: EVP_MD_CTX_new failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    int ret = -1;
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) <= 0) {
        printf("Debug: EVP_DigestInit_ex failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (EVP_DigestUpdate(md_ctx, input, input_len) <= 0) {
        printf("Debug: EVP_DigestUpdate failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    unsigned int output_len;
    if (EVP_DigestFinal_ex(md_ctx, output, &output_len) <= 0) {
        printf("Debug: EVP_DigestFinal_ex failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (output_len != SHA256_DIGEST_LEN) {
        printf("Debug: SHA-256 output length invalid, expected %d, got %u\n", SHA256_DIGEST_LEN, output_len);
        goto cleanup;
    }
    ret = 0;
cleanup:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

int openssl_hash_sha512(const uint8_t *input, size_t input_len, uint8_t *output) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("Debug: EVP_MD_CTX_new failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    int ret = -1;
    if (EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL) <= 0) {
        printf("Debug: EVP_DigestInit_ex failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (EVP_DigestUpdate(md_ctx, input, input_len) <= 0) {
        printf("Debug: EVP_DigestUpdate failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    unsigned int output_len;
    if (EVP_DigestFinal_ex(md_ctx, output, &output_len) <= 0) {
        printf("Debug: EVP_DigestFinal_ex failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (output_len != SHA512_DIGEST_LEN) {
        printf("Debug: SHA-512 output length invalid, expected %d, got %u\n", SHA512_DIGEST_LEN, output_len);
        goto cleanup;
    }
    ret = 0;
cleanup:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

int openssl_eddsa_generate_keypair(uint8_t *public_key, uint8_t *private_key) {
    if (!public_key || !private_key) {
        printf("Debug: Public key hoặc private key là null\n");
        return -1;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) {
        printf("Debug: EVP_PKEY_CTX_new_id failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Debug: EVP_PKEY_keygen_init failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("Debug: EVP_PKEY_keygen failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    size_t pub_len = ED25519_PUBLIC_KEY_LEN;
    size_t priv_len = ED25519_PRIVATE_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_len) <= 0) {
        printf("Debug: EVP_PKEY_get_raw_public_key failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, private_key, &priv_len) <= 0) {
        printf("Debug: EVP_PKEY_get_raw_private_key failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (pub_len != ED25519_PUBLIC_KEY_LEN || priv_len != ED25519_PRIVATE_KEY_LEN) {
        printf("Debug: Key length invalid, public: %zu, private: %zu\n", pub_len, priv_len);
        goto cleanup;
    }
    ret = 0;
cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int openssl_eddsa_sign(const uint8_t *private_key, const uint8_t *message, size_t message_len, uint8_t *signature) {
    if (!private_key || !signature || !message) {
        printf("Debug: Private key, message hoặc signature là null\n");
        return -1;
    }
    if (message_len == 0) {
        printf("Debug: Chiều dài thông điệp là 0\n");
        return -1;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key, ED25519_PRIVATE_KEY_LEN);
    if (pkey == NULL) {
        printf("Debug: EVP_PKEY_new_raw_private_key failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("Debug: EVP_MD_CTX_new failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(pkey);
        return -1;
    }
    int ret = -1;
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        printf("Debug: EVP_DigestSignInit failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    size_t sig_len = ED25519_SIGNATURE_LEN;
    if (EVP_DigestSign(md_ctx, signature, &sig_len, message, message_len) <= 0) {
        printf("Debug: EVP_DigestSign failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (sig_len != ED25519_SIGNATURE_LEN) {
        printf("Debug: Signature length invalid, expected %d, got %zu\n", ED25519_SIGNATURE_LEN, sig_len);
        goto cleanup;
    }
    ret = 0;
cleanup:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

int openssl_eddsa_verify(const uint8_t *public_key, const uint8_t *message, size_t message_len, const uint8_t *signature) {
    if (!public_key || !signature || !message) {
        printf("Debug: Dữ liệu đầu vào không hợp lệ (con trỏ null)\n");
        return -1;
    }
    if (message_len > 1024) {
        printf("Debug: Chiều dài thông điệp quá lớn\n");
        return -1;
    }
    if (message_len == 0) {
        printf("Debug: Chiều dài thông điệp là 0 (không hợp lệ)\n");
        return 1; // Invalid thay vì -1
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, ED25519_PUBLIC_KEY_LEN);
    if (pkey == NULL) {
        printf("Debug: EVP_PKEY_new_raw_public_key failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("Debug: EVP_MD_CTX_new failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(pkey);
        return -1;
    }

    int ret = -1;
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        printf("Debug: EVP_DigestVerifyInit failed, error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    int openssl_ret = EVP_DigestVerify(md_ctx, signature, ED25519_SIGNATURE_LEN, message, message_len);
    printf("Debug: EVP_DigestVerify returned %d\n", openssl_ret);
    if (openssl_ret == 1) {
        ret = 0; // Valid
    } else if (openssl_ret == 0) {
        ret = 1; // Invalid
    } else {
        printf("Debug: EVP_DigestVerify error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1; // Error
    }

cleanup:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

static crypto_backend_t openssl_backend = {
    .hash_sha256 = openssl_hash_sha256,
    .hash_sha512 = openssl_hash_sha512,
    .eddsa_generate_keypair = openssl_eddsa_generate_keypair,
    .eddsa_sign = openssl_eddsa_sign,
    .eddsa_verify = openssl_eddsa_verify
};

crypto_backend_t* get_crypto_backend(void) {
    return &openssl_backend;
}