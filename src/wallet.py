import ecdsa
import hashlib
import json
import binascii

# Generate a new wallet
def create_wallet():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()

    private_hex = private_key.to_string().hex()
    public_hex = public_key.to_string().hex()

    address = hashlib.sha256(public_key.to_string()).hexdigest()

    return {
        'address': address,
        'private_key': private_hex,
        'public_key': public_hex
    }

# Sign a transaction
def sign_transaction(private_hex, transaction_data):
    private_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_hex), curve=ecdsa.SECP256k1)
    message = json.dumps(transaction_data, sort_keys=True).encode()
    message_hash = hashlib.sha256(message).digest()
    signature = private_key.sign(message_hash)
    return signature.hex()

# Verify a transaction
def verify_signature(public_hex, transaction_data, signature_hex):
    public_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_hex), curve=ecdsa.SECP256k1)
    message = json.dumps(transaction_data, sort_keys=True).encode()
    message_hash = hashlib.sha256(message).digest()
    return public_key.verify(bytes.fromhex(signature_hex), message_hash)

# Example usage
if __name__ == "__main__":
    wallet = create_wallet()
    print("Address:", wallet['address'])
    print("Private Key:", wallet['private_key'])
    print("Public Key:", wallet['public_key'])
