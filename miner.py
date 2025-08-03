import os
import json
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

API_URL = 'https://sourceguy.pythonanywhere.com' # Change if your node runs elsewhere
WALLET_FILE = 'wallet.json'

def generate_wallet():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    wallet = {
        'private_key': priv_bytes.decode(),
        'public_key': pub_bytes.decode()
    }

    with open(WALLET_FILE, 'w') as f:
        json.dump(wallet, f)
    print('New wallet created and saved.')

def load_wallet():
    if not os.path.exists(WALLET_FILE):
        print('Wallet not found, generating new one...')
        generate_wallet()

    with open(WALLET_FILE, 'r') as f:
        wallet = json.load(f)
    return wallet

def get_address(pub_key_pem):
    # Simplified wallet address = SHA256 of public key PEM (hex)
    from hashlib import sha256
    return sha256(pub_key_pem.encode()).hexdigest()

def get_balance(address):
    try:
        r = requests.get(f'{API_URL}/get_balance', params={'address': address})
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

def main():
    wallet = load_wallet()
    address = get_address(wallet['public_key'])
    print('Wallet address:', address)

    while True:
        print('\nChoose an action:')
        print('1. Show balance')
        print('2. Mine a block')
        print("3. Start Mining")
        print('4. Exit')
        choice = input('> ').strip()

        if choice == '1':
            balance = get_balance(address)
            print(f'Balance for {address}: {balance}')
        elif choice == '2':
            mine(address)
        elif choice == '3':
            start_mining(address)
        elif choice == '4':
            print('Bye!')
            break
        else:
            print('Invalid choice.')

if __name__ == '__main__':
    main()
