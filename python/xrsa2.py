from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

def _verify(self, plain_data, signature, public_key):
    # See: https://anora.cn/article/35
    raw_key = RSA.importKey(base64.urlsafe_b64decode(public_key))
    raw_sign = base64.urlsafe_b64decode(signature + '=' * (4 - len(signature) % 4))
    raw_data = bytes(plain_data, 'utf-8')

    hash_value = SHA256.new(raw_data)
    verifier = PKCS1_v1_5.new(raw_key)
    return verifier.verify(hash_value, raw_sign)