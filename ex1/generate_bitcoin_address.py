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
        self._blockchain_address = self.generate_blockchain_address()

    @property
    def private_key(self):
        return self._private_key.to_string().hex()

    @property
    def public_key(self):
        return self._public_key.to_string().hex()

    @property
    def blockchain_address(self):
        return self._blockchain_address

    def generate_blockchain_address(self):
        # 2: SHA-256 for the public key
        public_key_bytes = self._public_key.to_string()
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()

        # 3: RIPMD160 for the SHA-256
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        #print("#3", ripemd160_bpk_hex)

        # 4: Add network byte
        # cf. https://en.bitcoin.it/wiki/List_of_address_prefixes
        network_byte = b'00' # P2PKH (Mainnet)
#        network_byte = b'05' # P2SH (Mainnet)
#        network_byte = b'6F' # P2PKH (Testnet)
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        #print("#4", network_bitcoin_public_key_bytes.hex())

        # 5: Double SHA-256
        sha256_bpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_bpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        #print("#5", sha256_hex)

        # 6: Get checksum
        checksum = sha256_hex[:8]
        #print("#6", checksum)

        # 7: Concatenate public key and checksum
        address_hex = network_bitcoin_public_key_bytes + codecs.decode(checksum, 'hex')
        #print("#7", address_hex.hex())

        # 8: Encoding the key with Base58
        blockchain_address = base58.b58encode(address_hex).decode('utf-8')
        #print("blockchain address of", self._name, ":", blockchain_address)
        #print("#8", blockchain_address)

        return blockchain_address


if __name__ == '__main__':
    wallet_A = Wallet("A")
    print("address    :", wallet_A.blockchain_address)
    print("public key :", wallet_A.public_key)
    print("private key:", wallet_A.private_key) # <-- This must be secret.


