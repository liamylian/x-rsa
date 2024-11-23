#ifndef RSAX_H
#define RSAX_H

#include <stdbool.h>

struct rsa_pub_key;
typedef struct rsa_pub_key rsa_pub_key_t;

struct rsa_pri_key;
typedef struct rsa_pri_key rsa_pri_key_t;


rsa_pub_key_t *rsa_public_key_from_file(const char *pub_key_path);

rsa_pub_key_t *rsa_public_key_from_str(const char *pub_key_str);

void rsa_public_key_free(rsa_pub_key_t *pub_key);


rsa_pri_key_t *rsa_private_key_from_file(const char *pri_key_path);

rsa_pri_key_t *rsa_private_key_from_str(const char *pri_key_str);

void rsa_private_key_free(rsa_pri_key_t *pri_key);


unsigned char *
rsa_public_encrypt(size_t *out_len, const rsa_pub_key_t *pub_key, const unsigned char *plain, size_t plain_len);

unsigned char *
rsa_private_decrypt(size_t *out_len, const rsa_pri_key_t *pri_key, const unsigned char *cipher, size_t cipher_len);


unsigned char *
rsa_private_encrypt(size_t *out_len, const rsa_pri_key_t *pri_key, const unsigned char *plain, size_t plain_len);

unsigned char *
rsa_public_decrypt(size_t *out_len, const rsa_pub_key_t *pub_key, const unsigned char *cipher, size_t cipher_len);


unsigned char *rsa_sign(size_t *out_len, const rsa_pri_key_t *pri_key, const unsigned char *plain, size_t plain_len);

bool
rsa_verify(const rsa_pub_key_t *pub_key, const unsigned char *plain, size_t plain_len, const unsigned char *signature,
           size_t signature_len);


#endif //RSAX_H
