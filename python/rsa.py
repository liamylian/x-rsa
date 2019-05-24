import rsa


def private_encrypt(data, private_key):
    rsa.sign(data, private_key, 'SHA-256')


def public_decrypt():
    pass
