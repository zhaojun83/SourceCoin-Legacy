import os
import json
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet, InvalidToken
from getpass import getpass
import base64
import hashlib


API_URL = 'https://sourceguy.pythonanywhere.com' # Change if your node runs elsewhere
WALLET_FILE = 'wallet.json'

def derive_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_private_key(private_key_pem: str, password: str) -> str:
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(private_key_pem.encode()).decode()

def decrypt_private_key(encrypted_pem: str, password: str) -> str:
    key = derive_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted_pem.encode()).decode()


def generate_wallet():
    print("Create a password for your wallet:")
    password = getpass("Password: ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        return generate_wallet()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Compute address from public key
    address = hashlib.sha256(pub_bytes).hexdigest()

    encrypted_priv = encrypt_private_key(priv_bytes.decode(), password)

    wallet = {
        'address': address,
        'private_key': encrypted_priv,
        'public_key': pub_bytes.decode()
    }

    with open(WALLET_FILE, 'w') as f:
        json.dump(wallet, f)
    print(f'New wallet created. Your address: {address}')

    with open(WALLET_FILE, 'w') as f:
        json.dump(wallet, f)
    print('New wallet created and saved securely.')


def load_wallet():
    if not os.path.exists(WALLET_FILE):
        print('Wallet not found, generating new one...')
        generate_wallet()

    with open(WALLET_FILE, 'r') as f:
        wallet = json.load(f)

    for _ in range(3):
        password = getpass("Enter your wallet password: ")
        try:
            decrypted_priv = decrypt_private_key(wallet['private_key'], password)
            wallet['private_key'] = decrypted_priv
            return wallet
        except InvalidToken:
            print("Wrong password.")
    print("Too many failed attempts.")
    exit(1)


def get_address(pub_key_pem):
    # Simplified wallet address = SHA256 of public key PEM (hex)
    from hashlib import sha256
    return sha256(pub_key_pem.encode()).hexdigest()

def get_balance(address):
    try:
        r = requests.get(f'{API_URL}/balance/{address}')
        if r.status_code == 200:
            return r.json().get('balance', 0)
        # else:
        #     print('Error getting balance:', r.text)
    except Exception as e:
        print('Error:', e)
    return 0

def mine(address):
    try:
        r = requests.get(f'{API_URL}/mine', params={'miner': address})
        if r.status_code == 200:
            data = r.json()
            print(f"Successfully mined block! Reward: {data['reward']}")
        else:
            print('Mining error:', r.json().get('message'))
    except Exception as e:
        print('Error during mining:', e)

def start_mining(address):
    while True:
        try:
            r = requests.get(f'{API_URL}/mine', params={'miner': address})
            if r.status_code == 200:
                data = r.json()
                print(f"Successfully mined block! Reward: {data['reward']}")
            else:
                print(r.json().get('message'))
        except Exception as e:
            print('Error during mining:', e)

def send_transaction(sender, public_key_pem, private_key_pem):
    receiver = input("Receiver's wallet address: ").strip()
    try:
        amount = float(input("Amount to send: "))
        fee = float(input("Transaction fee (suggest 0.1 - 1.0): "))
    except ValueError:
        print("Invalid number.")
        return

    signature = sign_transaction(private_key_pem, sender, receiver, amount, fee)

    tx = {
        'sender': sender,
        'receiver': receiver,
        'amount': amount,
        'fee': fee,
        'public_key': public_key_pem,
        'signature': signature
    }

    try:
        r = requests.post(f'{API_URL}/send', json=tx)
        if r.status_code == 201:
            print("Transaction submitted!")
        else:
            print("Error:", r.json())
    except Exception as e:
        print("Failed to send:", e)
        
def sign_transaction(private_key_pem, sender, receiver, amount, fee):
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    message = f"{sender}{receiver}{amount}{fee}".encode()
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

def main():
    wallet = load_wallet()
    address = get_address(wallet['public_key'])
    print('Wallet address:', address)

    while True:
        print('\nChoose an action:')
        print('1. Show balance')
        print('2. Mine a block')
        print("3. Start Mining")
        print("4. Send Coins")
        print('5. Exit')
        choice = input('> ').strip()

        if choice == '1':
            balance = get_balance(address)
            print(f'Balance for {address}: {balance}')
        elif choice == '2':
            mine(address)
        elif choice == '3':
            start_mining(address)
        elif choice == '4':
            send_transaction(address, wallet['public_key'], wallet['private_key'])
        elif choice == '5':
            print('Bye!')
            break
        else:
            print('Invalid choice.')



if __name__ == '__main__':
    main()


