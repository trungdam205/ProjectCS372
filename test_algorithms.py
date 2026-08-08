import unittest

from crypto_algorithms import (
    aes_decrypt,
    aes_encrypt,
    des_decrypt,
    des_encrypt,
    generate_3des_key,
    generate_aes_key,
    generate_des_key,
    triple_des_decrypt,
    triple_des_encrypt,
)


class TestSymmetricAlgorithms(unittest.TestCase):
    def setUp(self) -> None:
        self.algorithms = [
            (des_encrypt, des_decrypt, generate_des_key),
            (triple_des_encrypt, triple_des_decrypt, generate_3des_key),
            (aes_encrypt, aes_decrypt, generate_aes_key),
        ]
        self.samples = [
            b"",
            b"Hello",
            b"1234567890123456",
            "Tôi đang học mã hóa đối xứng".encode("utf-8"),
            b"A" * 1_000,
        ]

    def test_round_trip(self) -> None:
        for encrypt, decrypt, make_key in self.algorithms:
            for plaintext in self.samples:
                with self.subTest(algorithm=encrypt.__name__, size=len(plaintext)):
                    key = make_key()
                    result = encrypt(plaintext, key)
                    self.assertEqual(
                        decrypt(result.ciphertext, key, result.iv), plaintext
                    )

    def test_random_iv_changes_ciphertext(self) -> None:
        plaintext = b"same plaintext"
        for encrypt, _, make_key in self.algorithms:
            with self.subTest(algorithm=encrypt.__name__):
                key = make_key()
                first = encrypt(plaintext, key)
                second = encrypt(plaintext, key)
                self.assertNotEqual(first.iv, second.iv)
                self.assertNotEqual(first.ciphertext, second.ciphertext)

    def test_wrong_aes_key_does_not_recover_plaintext(self) -> None:
        plaintext = b"confidential experiment data"
        result = aes_encrypt(plaintext, generate_aes_key())
        try:
            recovered = aes_decrypt(
                result.ciphertext, generate_aes_key(), result.iv
            )
        except ValueError:  # Wrong keys normally cause invalid PKCS#7 padding.
            return
        self.assertNotEqual(recovered, plaintext)


if __name__ == "__main__":
    unittest.main(verbosity=2)
