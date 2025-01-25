import os
from ecdsa import SigningKey, SECP256k1
from hashlib import sha256, new
import base58


def generate_private_key():
    #   A private key is a 256-bit random number
    return os.urandom(32)


def generate_public_key(private_key):
    print("1. Private key:\n", private_key.hex())
    #   Use SECP256k1 curve
    private_key = SigningKey.from_string(private_key, curve=SECP256k1)

    #   Get the public key from the private key
    public_key = private_key.get_verifying_key()

    #   Compress public key
    if public_key.pubkey.point.y() % 2 == 0:
        print("2. Public key:\n02" + public_key.to_string().hex())
        return b'\x02' + public_key.pubkey.point.x().to_bytes(32, 'big')
    else:
        print("2. Public key:\n03" + public_key.to_string().hex())
        return b'\x03' + public_key.pubkey.point.x().to_bytes(32, 'big')


def generate_address(public_key):
    #   SHA256(🔑)
    sha256_hash = sha256(public_key).digest()

    #   RIPEMD160(SHA256(🔑))
    fingerprint = new('ripemd160', sha256_hash).hexdigest()
    print("3. Hashed public key:\n", fingerprint)

    #   Add version byte (0x00 for mainnet)
    versioned_fingerprint = bytes.fromhex("00" + fingerprint)
    print("4. Hashed public key with version byte:\n", versioned_fingerprint.hex())

    #   First 4 bytes of SHA256(SHA256(fingerprint))
    checksum = sha256(sha256(versioned_fingerprint).digest()).digest()[:4]
    print("5. Checksum:\n", checksum.hex())

    #   Append the checksum to the versioned hash
    binary_btc_address = versioned_fingerprint + checksum
    print("6. Binary Bitcoin address:\n", binary_btc_address.hex())

    #   Convert to Base58
    final_btc_address = base58.b58encode(binary_btc_address).decode()
    print("7. Final Bitcoin address:\n", final_btc_address)
    return final_btc_address


def generate_bitcoin_address_P2PKH():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    address = generate_address(public_key)
    return private_key.hex(), address


if __name__ == "__main__":
    private_key, address = generate_bitcoin_address_P2PKH()
