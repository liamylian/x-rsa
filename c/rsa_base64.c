#include <malloc.h>

#include "base64.h"
#include "rsa.h"

#include "rsa_base64.h"

unsigned char *public_encrypt(const rsa_pub_key_t *pub_key, const unsigned char *plain, size_t plain_len) {

    unsigned char *cipher, *cipher_base64;
    size_t cipher_len, cipher_text_len;

    cipher = rsa_public_encrypt(&cipher_len, pub_key, plain, plain_len);
    if (cipher == NULL) {
        return NULL;
    }

    cipher_base64 = base64_encode(&cipher_text_len, cipher, cipher_len);

    free(cipher);
    return cipher_base64;
}

unsigned char *
private_decrypt(const rsa_pri_key_t *pri_key, const unsigned char *cipher_base64, size_t cipher_base64_len) {

    unsigned char *cipher, *plain;
    size_t plain_len, plain_txt_len;


    cipher = base64_decode(&plain_len, cipher_base64, cipher_base64_len);
    if (cipher == NULL) {
        return NULL;
    }

    plain = rsa_private_decrypt(&plain_txt_len, pri_key, cipher, plain_len);

    free(cipher);
    return plain;
}

unsigned char *private_encrypt(const rsa_pri_key_t *pri_key, const unsigned char *plain, size_t plain_len) {

    unsigned char *cipher, *cipher_base64;
    size_t cipher_len, cipher_base64_len;

    cipher = rsa_private_encrypt(&cipher_len, pri_key, plain, plain_len);
    if (cipher == NULL) {
        return NULL;
    }

    cipher_base64 = base64_encode(&cipher_base64_len, cipher, cipher_len);

    free(cipher);
    return cipher_base64;
}

unsigned char *
public_decrypt(const rsa_pub_key_t *pub_key, const unsigned char *cipher_base64, size_t cipher_base64_len) {

    unsigned char *cipher, *plain;
    size_t cipher_len, plain_len;

    cipher = base64_decode(&cipher_len, cipher_base64, cipher_base64_len);
    if (cipher == NULL) {
        return NULL;
    }

    plain = rsa_public_decrypt(&plain_len, pub_key, cipher, cipher_len);

    free(cipher);
    return plain;
}

unsigned char *private_sign(const rsa_pri_key_t *pri_key, const unsigned char *plain, size_t plain_len) {

    unsigned char *sign, *sign_base64;
    size_t sign_len, sign_base64_len;

    sign = rsa_sign(&sign_len, pri_key, plain, plain_len);
    if (sign == NULL) {
        return NULL;
    }

    sign_base64 = base64_encode(&sign_base64_len, sign, sign_len);
    free(sign);
    return sign_base64;
}

bool public_verify(const rsa_pub_key_t *pub_key, const unsigned char *plain, size_t plain_len,
                   const unsigned char *sign_base64,
                   size_t sign_base64_len) {

    unsigned char *sign;
    size_t sign_len;

    sign = base64_decode(&sign_len, sign_base64, sign_base64_len);
    if (sign == NULL) {
        return false;
    }

    bool res = rsa_verify(pub_key, plain, plain_len, sign, sign_len);
    free(sign);
    return res;
}
