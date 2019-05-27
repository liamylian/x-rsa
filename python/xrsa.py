import base64

import rsa

RSA_SIGN_METHOD = 'SHA-256'


class XRsa:
    def __init__(self, public_key: str, private_key: str):
        self._public_key = rsa.PublicKey.load_pkcs1(public_key.encode())
        self._private_key = rsa.PrivateKey.load_pkcs1(private_key.encode())

    @staticmethod
    def create_keys(key_size=2048):
        (pub_key, pri_key) = rsa.newkeys(key_size)
        return (
            pub_key.save_pkcs1().decode(),
            pri_key.save_pkcs1().decode()
        )

    def public_encrypt(self, data: str) -> str:
        part_len = int(self._public_key.n.bit_length() / 8 - 11)
        data_len = len(data)

        pos = 0
        encrypted = bytes()
        while pos < data_len:
            part = data[pos:pos + part_len]
            part_encrypted = rsa.encrypt(part.encode(), self._public_key)
            encrypted += part_encrypted
            pos += part_len

        return base64.urlsafe_b64encode(encrypted).decode()

    def private_decrypt(self, encrypted_data: str) -> str:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        data_len = len(encrypted_bytes)
        part_len = self._public_key.n.bit_length()

        pos = 0
        decrypted = ''
        while pos < data_len:
            part = encrypted_bytes[pos:pos + part_len]
            part_decrypted = rsa.decrypt(part, self._private_key)
            decrypted += part_decrypted.decode()
            pos += part_len

        return decrypted

    def sign(self, data: str):
        sign = rsa.sign(data.encode(), self._private_key, RSA_SIGN_METHOD)
        return base64.urlsafe_b64encode(sign).decode()

    def verify(self, data: str, sign: str):
        try:
            rsa.verify(data.encode(), base64.urlsafe_b64decode(sign.encode()), self._public_key)
            return True
        except Exception:
            return False
