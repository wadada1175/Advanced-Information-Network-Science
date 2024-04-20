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
        network_byte = b'00' # P2PKH
        #network_byte = b'05' # P2SH
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


class Transaction(object):

    def __init__(self, sender_private_key, sender_public_key,
                 sender_blockchain_address, recipient_blockchain_address,
                 value):
        self.sender_private_key = sender_private_key
        self.sender_public_key = sender_public_key
        self.sender_blockchain_address = sender_blockchain_address
        self.recipient_blockchain_address = recipient_blockchain_address
        self.value = value

    def generate_signature(self):
        sha256 = hashlib.sha256()
        transaction = {
            'sender_blockchain_address': self.sender_blockchain_address,
            'recipient_blockchain_address': self.recipient_blockchain_address,
            'value': float(self.value)
        }
        sha256.update(str(transaction).encode('utf-8'))
        message_digest = sha256.digest()
        private_key = SigningKey.from_string(bytes().fromhex(self.sender_private_key), curve=NIST256p)
        private_key_sign = private_key.sign(message_digest)
        signature = private_key_sign.hex()
        #return transaction, message_digest.hex(), signature
        return transaction, message_digest.hex(), signature


if __name__ == '__main__':
    wallet_A = Wallet("A")
    print("-"*20)
    print("address    :", wallet_A.blockchain_address)
    print("public key :", wallet_A.public_key)
    print("private key:", wallet_A.private_key) # <-- This must be secret.

    wallet_B = Wallet("B")
    print("-"*20)
    print("address    :", wallet_B.blockchain_address)
    print("public key :", wallet_B.public_key)
    print("private key:", wallet_B.private_key) # <-- This must be secret.
   


    tx = Transaction(wallet_A.private_key, wallet_A.public_key, wallet_A.blockchain_address,
                     wallet_B.blockchain_address, 1.0)
    tx_str, message_digest, signature = tx.generate_signature()
    print("-"*20)
    print("transaction:", tx_str)
    print("message digest of transaction:", message_digest)
    print("signature:", signature)

