import os
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import keccak


def generate_private_key():
    #   A private key is a 256-bit random number
    return os.urandom(32)


def generate_public_key(private_key):
    print("1. Private key:\n", private_key.hex())
    #   Use SECP256k1 curve
    private_key = SigningKey.from_string(private_key, curve=SECP256k1)

    #   Get the public key from the private key
    public_key = private_key.get_verifying_key()
    x = public_key.pubkey.point.x().to_bytes(32, 'big')
    y = public_key.pubkey.point.y().to_bytes(32, 'big')

    print("2. Public key:\n" + (x+y).hex())
    return x + y


def generate_address(public_key):
    #   KECCAK256(🔑)  
    keccak_hash = keccak.new(digest_bits=256, data=public_key).hexdigest()
    print("2. Hashed public key:\n" + keccak_hash)
    #   Take the last 20 bytes from the hashed public key
    last_bytes = keccak_hash[-40:]
    print("3. Last 20 bytes of the hashed public key:\n" + last_bytes)
    #   Add 0x as prefix to get the final ETH address
    eth_address = '0x' + last_bytes
    print("4. Final Ethereum address:\n" + eth_address)
    return eth_address


def generate_ethereum_address():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    address = generate_address(public_key)
    return private_key.hex(), address


if __name__ == "__main__":
    private_key, address = generate_ethereum_address()
