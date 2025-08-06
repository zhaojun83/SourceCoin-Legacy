import hashlib
import json
import time
from flask import Flask, jsonify, request
from uuid import uuid4
import requests
from urllib.parse import urlparse
import random
import atexit
import os
from imports.consts import DAY, CHAIN_FILE, TX_FILE

def save_blockchain_state():
    with open(CHAIN_FILE, "w") as f:
        json.dump(blockchain.chain, f)
    with open(TX_FILE, "w") as f:
        json.dump(blockchain.pending_transactions, f)

def load_blockchain_state():
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE) as f:
            blockchain.chain = json.load(f)
    if os.path.exists(TX_FILE):
        with open(TX_FILE) as f:
            blockchain.pending_transactions = json.load(f)



class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.balances = {}  # Confirmed balances
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()

    def add_node(self, address):
        parsed = urlparse(address)
        self.nodes.add(parsed.netloc)

    def get_difficulty(self, block_index):
        """Dynamic difficulty adjustment - increases over time"""
        base_difficulty = 5  # Start with 5 leading zeros instead of 4
        
        # Increase difficulty every 50 blocks
        difficulty_adjustment = block_index // 50
        
        # Maximum difficulty of 8 leading zeros
        return min(base_difficulty + difficulty_adjustment, 8)

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        for i in range(1, len(chain)):
            block = chain[i]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_val = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            
            # Use dynamic difficulty based on block index
            required_difficulty = self.get_difficulty(block['index'])
            required_zeros = '0' * required_difficulty
            
            if hash_val[:required_difficulty] != required_zeros:
                return False
            previous_block = block
        return True

    def replace_chain(self):
        longest = self.chain
        max_length = len(self.chain)

        for node in self.nodes:
            try:
                res = requests.get(f'http://{node}/chain')
                if res.status_code == 200:
                    data = res.json()
                    length = data['length']
                    chain = data['chain']
                    if length > max_length and self.is_chain_valid(chain):
                        max_length = length
                        longest = chain
            except:
                continue

        if longest != self.chain:
            self.chain = longest
            return True
        return False

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.pending_transactions,
            'proof': proof,
            'previous_hash': previous_hash
        }

        # Apply each transaction to the balances
        for tx in self.pending_transactions:
            sender = tx['sender']
            receiver = tx['receiver']
            amount = tx['amount']

            if sender != "Network":
                self.balances[sender] = self.balances.get(sender, 0) - amount
            self.balances[receiver] = self.balances.get(receiver, 0) + amount

        self.pending_transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        block_index = len(self.chain) + 1  # Next block index
        difficulty = self.get_difficulty(block_index)
        required_zeros = '0' * difficulty
        
        while True:
            hash_val = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_val[:difficulty] == required_zeros:
                return new_proof
            new_proof += 1

    def hash(self, block):
        encoded = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()
    def is_valid_transaction(self, tx):
        required_fields = ['sender', 'receiver', 'amount', 'fee', 'public_key', 'signature']
        if not all(k in tx for k in required_fields):
            return False

        if tx['sender'] == 'Network':
            return True  # reward tx

        # Check fee and amount
        if tx['amount'] <= 0 or tx['fee'] < 0:
            return False

        sender_balance = self.get_balance(tx['sender'])
        total_cost = tx['amount'] + tx['fee']
        if sender_balance < total_cost:
            return False

        # Verify public key belongs to sender
        from hashlib import sha256
        expected_address = sha256(tx['public_key'].encode()).hexdigest()
        if expected_address != tx['sender']:
            return False

        # Verify signature
        try:
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.exceptions import InvalidSignature

            pub_key = serialization.load_pem_public_key(tx['public_key'].encode())
            message = f"{tx['sender']}{tx['receiver']}{tx['amount']}{tx['fee']}".encode()
            pub_key.verify(
                bytes.fromhex(tx['signature']),
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception:
            return False

        return True


    def add_transaction(self, tx):
        if not self.is_valid_transaction(tx):
            return False
        self.pending_transactions.append(tx)
        return self.get_previous_block()['index'] + 1

    def get_balance(self, address):
        return self.balances.get(address, 0)

# ------------------ Flask API ------------------

app = Flask(__name__)
node_address = str(uuid4()).replace('-', '')
blockchain = Blockchain()

BLOCK_TIME_SECONDS = random.randint(600, 1200)  # Increased from 299-600 to 600-1200 seconds (10-20 minutes)
HALVING_INTERVAL = 10     # Halve reward every 10 blocks (for demo)

@app.route('/mine', methods=['GET'])
def mine_block():
    miner = request.args.get('miner')
    if not miner:
        return 'Missing ?miner=your_address', 400

    last_block = blockchain.get_previous_block()
    now = time.time()
    time_since_last = now - last_block['timestamp']

    if time_since_last < BLOCK_TIME_SECONDS:
        wait_time = int(BLOCK_TIME_SECONDS - time_since_last)
        return jsonify({
            'message': f'Failed'
        }), 429

    # Halving logic
    reward_base = 50
    halvings = (last_block['index'] // HALVING_INTERVAL)
    reward = reward_base // (2 ** halvings)
    if reward == 0:
        reward = 1  # Minimum reward

    proof = blockchain.proof_of_work(last_block['proof'])
    prev_hash = blockchain.hash(last_block)

    # Calculate total fees in pending transactions
    total_fees = sum(tx.get('fee', 0) for tx in blockchain.pending_transactions)

    # Miner reward includes base reward + fees
    total_reward = reward + total_fees

    reward_tx = {
        'sender': 'Network',
        'receiver': miner,
        'amount': total_reward,
        'fee': 0,
        'public_key': '',
        'signature': ''
    }
    blockchain.pending_transactions.append(reward_tx)

    block = blockchain.create_block(proof, prev_hash)

    return jsonify({
        'message': 'Block mined!',
        'reward': total_reward,
        'block': block
    }), 200
    save_blockchain_state()

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    data = request.get_json()
    if not data:
        return 'No data provided', 400

    if not blockchain.is_valid_transaction(data):
        return jsonify({'message': 'Invalid or unauthorized transaction'}), 400

    blockchain.pending_transactions.append(data)

    # Broadcast to peers
    for node in blockchain.nodes:
        try:
            requests.post(f'http://{node}/broadcast_transaction', json=data)
        except:
            continue

    index = blockchain.get_previous_block()['index'] + 1
    return jsonify({'message': f'Transaction will be added to block {index}'}), 201


@app.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

@app.route('/chain', methods=['GET'])
def get_chain():
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }), 200

@app.route('/connect_node', methods=['POST'])
def connect_node():
    nodes = request.get_json().get('nodes')
    if not nodes:
        return "No nodes provided", 400
    for node in nodes:
        blockchain.add_node(node)
    return jsonify({
        'message': 'Nodes connected!',
        'total_nodes': list(blockchain.nodes)
    }), 201

@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    replaced = blockchain.replace_chain()
    if replaced:
        return jsonify({
            'message': 'Chain was replaced with the longest one',
            'new_chain': blockchain.chain
        }), 200
    else:
        return jsonify({
            'message': 'Current chain is already the longest',
            'chain': blockchain.chain
        }), 200
    
# @app.route('/timer2', methods=["GET"])
# def timer2():
#     try:
#         timer = DAY - 1  # Make sure DAY is an integer
#         return jsonify({
#             'message': timer
#         }), 200
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

@app.route('/send', methods=['POST'])
def send_transaction():
    tx = request.get_json()
    if not tx:
        return 'Missing transaction data', 400

    if blockchain.is_valid_transaction(tx):
        blockchain.pending_transactions.append(tx)
        return jsonify({'message': 'Transaction added'}), 201
    else:
        return jsonify({'error': 'Invalid transaction'}), 400


@app.route('/broadcast_transaction', methods=['POST'])
def broadcast_transaction():
    tx = request.get_json()
    if not tx:
        return 'Missing transaction data', 400

    if not blockchain.is_valid_transaction(tx):
        return jsonify({'message': 'Invalid transaction'}), 400

    blockchain.pending_transactions.append(tx)
    return jsonify({'message': 'Transaction received and added'}), 201

@app.route('/broadcast_block', methods=['POST'])
def broadcast_block():
    block = request.get_json().get('block')
    if not block:
        return 'No block provided', 400

    # Don't re-mine — just add if previous hash matches
    prev_block = blockchain.get_previous_block()
    if block['previous_hash'] == blockchain.hash(prev_block):
        blockchain.chain.append(block)
        return jsonify({'message': 'Block added'}), 200
        save_blockchain_state()
    else:
        return jsonify({'message': 'Invalid block, ignored'}), 400


@app.route('/', methods=['GET'])
def home():
    return 'Blockchain Running.'

if __name__ == '__main__':
    blockchain = Blockchain()
    load_blockchain_state()
    atexit.register(save_blockchain_state)
    app.run(port=5000)

