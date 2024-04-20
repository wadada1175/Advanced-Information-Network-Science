import base58
import codecs
import hashlib
from ecdsa import NIST256p
from ecdsa import SigningKey


class Wallet(object):

    def __init__(self, name="Miner"):
        self._name = name
        self._private_key = SigningKey.generate(curve=NIST256p)
        self._public_key = self._private_key.get_verifying_key()

    @property
    def private_key(self):
        return self._private_key.to_string().hex()

    @property
    def public_key(self):
        return self._public_key.to_string().hex()

    def generate_blockchain_address(self):
        while True:
            self._private_key = SigningKey.generate(curve=NIST256p)
            self._public_key = self._private_key.get_verifying_key()

            public_key_bytes = self._public_key.to_string()
            sha256_bpk = hashlib.sha256(public_key_bytes)
            sha256_bpk_digest = sha256_bpk.digest()

            ripemd160_bpk = hashlib.new('ripemd160')
            ripemd160_bpk.update(sha256_bpk_digest)
            ripemd160_bpk_digest = ripemd160_bpk.digest()
            ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')

            network_byte = b'00'
            network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
            network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')

            sha256_bpk = hashlib.sha256(network_bitcoin_public_key_bytes)
            sha256_bpk_digest = sha256_bpk.digest()
            sha256_2_nbpk = hashlib.sha256(sha256_bpk_digest)
            sha256_2_nbpk_digest = sha256_2_nbpk.digest()
            sha256_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')

            checksum = sha256_hex[:8]

            address_hex = network_bitcoin_public_key_bytes + codecs.decode(checksum, 'hex')
            blockchain_address = base58.b58encode(address_hex).decode('utf-8').lower()

            # Print generated values
            print("Generated address:", blockchain_address)
            print("Public key:", self.public_key)
            print("Private key:", self.private_key)

            # Check if the address contains a case-insensitive part of 'DaikiWada' (4 chars or more)
            target_substrings = ["".join(perm).lower() for perm in self.permutations_of_substring('DaikiWada', 4)]
            if any(sub in blockchain_address for sub in target_substrings):
                print("Target address found!")
                return blockchain_address

    def permutations_of_substring(self, text, min_length):
        length = len(text)
        for start in range(length):
            for end in range(start + min_length, length + 1):
                yield text[start:end]

if __name__ == '__main__':
    wallet_A = Wallet("A")
    wallet_A.generate_blockchain_address()
