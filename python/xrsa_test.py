import unittest
from python import xrsa


class TestXrsa(unittest.TestCase):
    def test_create_keys(self):
        (pub_key, pri_key) = xrsa.XRsa.create_keys()
        self.assertIsNotNone(pub_key)
        self.assertIsNotNone(pri_key)

    def test_public_encrypt_private_decrypt(self):
        (pub_key, pri_key) = xrsa.XRsa.create_keys()
        coder = xrsa.XRsa(pub_key, pri_key)

        data = 'Hello, XRSA'
        encrypted = coder.public_encrypt(data)
        decoded = coder.private_decrypt(encrypted)
        sign = coder.sign(data)
        gg = coder.verify(data, sign)
        print(encrypted)
        print(decoded)
        print(gg)
