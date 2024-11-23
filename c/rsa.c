#include <stdio.h>
#include <memory.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
//#include <openssl/err.h>

#include "rsa.h"

struct rsa_pub_key {
    RSA *rsa_key;
    EVP_PKEY *evp_key;
};

struct rsa_pri_key {
    RSA *rsa_key;
    EVP_PKEY *evp_key;
};

rsa_pub_key_t *rsa_public_key_from_file(const char *pub_key_path) {

    rsa_pub_key_t *pub_key = NULL;
    RSA *rsa_publicKey = NULL;
    FILE *fp_publicKey = NULL;

    if ((fp_publicKey = fopen(pub_key_path, "r")) == NULL) {
        return NULL;
    }

    if ((rsa_publicKey = PEM_read_RSA_PUBKEY(fp_publicKey, NULL, NULL, NULL)) == NULL) {
        goto END;
    }

    EVP_PKEY *evp_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_key, rsa_publicKey);

    pub_key = malloc(sizeof(rsa_pub_key_t));
    pub_key->rsa_key = rsa_publicKey;
    pub_key->evp_key = evp_key;

    END:
    fclose(fp_publicKey);
    return pub_key;
}

rsa_pub_key_t *rsa_public_key_from_str(const char *pub_key_str) {

    rsa_pub_key_t *pub_key = NULL;
    BIO *bio = NULL;
    RSA *rsa_publicKey = NULL;
    if ((bio = BIO_new_mem_buf(pub_key_str, -1)) == NULL) {
        return NULL;
    }

    rsa_publicKey = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if (!rsa_publicKey) {
        goto END;
    }

    EVP_PKEY *evp_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_key, rsa_publicKey);

    pub_key = malloc(sizeof(rsa_pub_key_t));
    pub_key->rsa_key = rsa_publicKey;
    pub_key->evp_key = evp_key;

    END:
    BIO_free_all(bio);
    return pub_key;
}

void rsa_public_key_free(rsa_pub_key_t *pub_key) {

    if (pub_key && pub_key->rsa_key) {
        // 这里不需要再调用 RSA_free(pri_key->rsa_key)
        EVP_PKEY_free(pub_key->evp_key);
    }
    if (pub_key) {
        free(pub_key);
    }
}

rsa_pri_key_t *rsa_private_key_from_file(const char *pri_key_path) {

    rsa_pri_key_t *pri_key = NULL;
    RSA *rsa_privateKey = NULL;
    FILE *fp_privateKey = NULL;

    if ((fp_privateKey = fopen(pri_key_path, "r")) == NULL) {
        return NULL;
    }

    if ((rsa_privateKey = PEM_read_RSAPrivateKey(fp_privateKey, NULL, NULL, NULL)) == NULL) {
        goto END;
    }

    EVP_PKEY *evp_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_key, rsa_privateKey);

    pri_key = malloc(sizeof(rsa_pri_key_t));
    pri_key->rsa_key = rsa_privateKey;
    pri_key->evp_key = evp_key;

    END:
    fclose(fp_privateKey);
    return pri_key;
}

rsa_pri_key_t *rsa_private_key_from_str(const char *pri_key_str) {

    rsa_pri_key_t *pri_key = NULL;
    BIO *bio = NULL;
    RSA *rsa_privateKey = NULL;
    if ((bio = BIO_new_mem_buf(pri_key_str, -1)) == NULL) {
        return NULL;
    }

    rsa_privateKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (!rsa_privateKey) {
        goto END;
    }

    EVP_PKEY *evp_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_key, rsa_privateKey);

    pri_key = malloc(sizeof(rsa_pri_key_t));
    pri_key->rsa_key = rsa_privateKey;
    pri_key->evp_key = evp_key;

    END:
    BIO_free_all(bio);
    return pri_key;
}

void rsa_private_key_free(rsa_pri_key_t *pri_key) {

    if (pri_key && pri_key->rsa_key) {
        // 这里不需要再调用 RSA_free(pri_key->rsa_key)
        EVP_PKEY_free(pri_key->evp_key);
    }
    if (pri_key) {
        free(pri_key);
    }
}

unsigned char *
rsa_public_encrypt(size_t *out_len, const rsa_pub_key_t *pub_key, const unsigned char *plain, size_t plain_len) {

    int pub_key_len = RSA_size(pub_key->rsa_key);
    int chunk_length = pub_key_len - 11;
    size_t num_of_chunks = (plain_len / chunk_length) + 1;
    size_t encrypted_size = (num_of_chunks * pub_key_len);

    unsigned char plain_chunk_buf[chunk_length];
    unsigned char cipher_chunk_buf[pub_key_len];

    unsigned char *cipher = malloc(encrypted_size + 1);
    int cipher_index = 0;

    for (int i = 0; i < plain_len; i += chunk_length) {
        memcpy(&plain_chunk_buf[0], &plain[i], chunk_length);
        int cipher_chunk_len = RSA_public_encrypt(chunk_length, plain_chunk_buf, cipher_chunk_buf, pub_key->rsa_key,
                                                  RSA_PKCS1_PADDING);
        if (cipher_chunk_len == -1) {
            // ERR_load_CRYPTO_strings();
            // fprintf(stderr, "Error %s\n", ERR_error_string(ERR_get_error(), err));
            // fprintf(stderr, "Error %s\n", err);
            free(cipher);
            return NULL;
        }

        memcpy(&cipher[cipher_index], &cipher_chunk_buf[0], cipher_chunk_len);
        cipher_index += cipher_chunk_len;
    }

    *out_len = encrypted_size;
    return cipher;
}

unsigned char *
rsa_private_decrypt(size_t *out_len, const rsa_pri_key_t *pri_key, const unsigned char *cipher, size_t cipher_len) {

    int pri_key_len = RSA_size(pri_key->rsa_key);

    unsigned char cipher_chunk_buf[pri_key_len];
    unsigned char plain_chunk_buf[cipher_len];

    unsigned char *plain = malloc(cipher_len);
    size_t plain_len = 0;
    memset(plain, 0, cipher_len);

    for (int i = 0; i < cipher_len; i += pri_key_len) {
        memcpy(&cipher_chunk_buf[0], &cipher[i], pri_key_len);

        // 分段长度必须为： 密钥长度 - 11
        int result_length = RSA_private_decrypt(pri_key_len, cipher_chunk_buf, plain_chunk_buf, pri_key->rsa_key,
                                                RSA_PKCS1_PADDING);
        if (result_length == -1) {
            // ERR_load_CRYPTO_strings();
            // fprintf(stderr, "Error %s\n", ERR_error_string(ERR_get_error(), err));
            // fprintf(stderr, "Error %s\n", err);
            free(plain);
            return NULL;
        }

        memcpy(&plain[plain_len], plain_chunk_buf, result_length);
        plain_len = result_length;
    }

    *out_len = plain_len;
    return plain;
}

unsigned char *
rsa_private_encrypt(size_t *out_len, const rsa_pri_key_t *pri_key, const unsigned char *plain, size_t plain_len) {

    int pri_key_len = RSA_size(pri_key->rsa_key);
    int chunk_len = pri_key_len - 11;
    int num_of_chunks = ((int) plain_len / chunk_len) + 1;
    int encrypted_size = (num_of_chunks * pri_key_len);

    unsigned char *cipher = malloc(encrypted_size + 1);
    int cipher_index = 0;

    unsigned char plain_chunk_buf[chunk_len];
    unsigned char cipher_chunk_buf[pri_key_len];

    for (int i = 0; i < plain_len; i += chunk_len) {
        memcpy(&plain_chunk_buf[0], &plain[i], chunk_len);

        int result_length = RSA_private_encrypt(chunk_len, plain_chunk_buf, cipher_chunk_buf, pri_key->rsa_key,
                                                RSA_PKCS1_PADDING);
        if (result_length == -1) {
            //ERR_load_CRYPTO_strings();
            //fprintf(stderr, "Error %s\n", ERR_error_string(ERR_get_error(), err));
            //fprintf(stderr, "Error %s\n", err);
            free(cipher);
            return NULL;
        }

        memcpy(&cipher[cipher_index], &cipher_chunk_buf[0], result_length);
        cipher_index += result_length;
    }

    *out_len = encrypted_size;
    return cipher;
}

unsigned char *
rsa_public_decrypt(size_t *out_len, const rsa_pub_key_t *pub_key, const unsigned char *cipher, size_t cipher_len) {

    int rsa_public_len = RSA_size(pub_key->rsa_key);
    unsigned char cipher_chunk_buf[rsa_public_len];
    unsigned char plain_chunk_buf[cipher_len];


    unsigned char *plain = malloc(cipher_len);
    size_t plain_index = 0;
    memset(plain, 0, cipher_len);

    for (int i = 0; i < cipher_len; i += rsa_public_len) {
        memcpy(&cipher_chunk_buf[0], &cipher[i], rsa_public_len);

        int result_length = RSA_public_decrypt(rsa_public_len, cipher_chunk_buf, plain_chunk_buf, pub_key->rsa_key,
                                               RSA_PKCS1_PADDING);
        if (result_length == -1) {
            // ERR_load_CRYPTO_strings();
            // fprintf(stderr, "Error %s\n", ERR_error_string(ERR_get_error(), err));
            // fprintf(stderr, "Error %s\n", err);
            free(plain);
            return NULL;
        }

        memcpy(&plain[plain_index], plain_chunk_buf, result_length);
        plain_index += result_length;
    }

    *out_len = plain_index;
    return plain;
}

unsigned char *rsa_sign(size_t *out_len, const rsa_pri_key_t *pri_key, const unsigned char *plain, size_t plain_len) {

    int size = EVP_PKEY_size(pri_key->evp_key);

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);
    EVP_SignInit_ex(ctx, EVP_sha256(), NULL);
    EVP_SignUpdate(ctx, plain, plain_len);

    unsigned char *md = malloc(size);
    unsigned int md_len = 0;
    EVP_SignFinal(ctx, md, &md_len, pri_key->evp_key);

    EVP_MD_CTX_destroy(ctx);
    *out_len = md_len;
    return md;
}

bool
rsa_verify(const rsa_pub_key_t *pub_key, const unsigned char *plain, size_t plain_len, const unsigned char *signature,
           size_t signature_len) {

    int res;

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);
    EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL);
    EVP_VerifyUpdate(ctx, plain, plain_len);

    res = EVP_VerifyFinal(ctx, signature, signature_len, pub_key->evp_key);

    EVP_MD_CTX_destroy(ctx);
    return res;
}
