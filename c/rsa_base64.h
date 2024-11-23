#ifndef RSA_BASE64_H
#define RSA_BASE64_H

#include <stddef.h>
#include "rsa.h"

unsigned char *public_encrypt(const rsa_pub_key_t *pub_key, const unsigned char *plain, size_t plain_len);

unsigned char *
private_decrypt(const rsa_pri_key_t *pri_key, const unsigned char *cipher_base64, size_t cipher_base64_len);

unsigned char *private_encrypt(const rsa_pri_key_t *pri_key, const unsigned char *plain, size_t plain_len);

unsigned char *
public_decrypt(const rsa_pub_key_t *pub_key, const unsigned char *cipher_base64, size_t cipher_base64_len);

unsigned char *private_sign(const rsa_pri_key_t *pri_key, const unsigned char *plain, size_t plain_len);

bool public_verify(const rsa_pub_key_t *pub_key, const unsigned char *plain, size_t plain_len,
                   const unsigned char *sign_base64, size_t sign_base64_len);

#endif //RSA_BASE64_H
