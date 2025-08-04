### ! Doesnt work yet ! ###

import os
from imports.consts import WALLET_FILE, API_URL
from getpass import getpass
import json
from miner import decrypt_private_key
from cryptography.fernet import InvalidToken
import requests

def load_wallet():
    if not os.path.exists(WALLET_FILE):
        print("Wallet not found, please create one by running miner.py")
        input()
        exit(0)

    with open(WALLET_FILE, 'r') as f:
        wallet = json.load(f)

    for _ in range(3):
        password = getpass("Enter your wallet password: ")
        try:
            decrypted_priv = decrypt_private_key(wallet["private_key"], password)
            wallet["private_key"] = decrypted_priv
            return wallet
        except InvalidToken:
            print("Wrong password.")
    print("Too many failed attempts.")
    exit(1)

# def timer():
#     response = requests.get(f"{API_URL}/timer2")
#     # print(response)
#     for key in response.json():
#         while response.json()[key] != 0:
#             print(response.json()[key])
#             if os.name == "nt":
#                 os.system("CLS") # Works on windows
#             else:
#                 os.system("clear")


# if __name__ == "__main__":
#     load_wallet()
#     timer()